"""CVE embeddings service for semantic search.

This module provides functionality to generate and manage embeddings for CVE
data using fastembed. It uses the all-MiniLM-L6-v2 model which offers excellent
speed/quality tradeoff for semantic similarity tasks.

The embeddings are computed from the concatenation of CVE title and description,
enabling semantic search capabilities across the CVE database.

Note: This module requires the optional 'semantic' dependencies:
    pip install cvec[semantic]
    # or with uv:
    uv pip install cvec[semantic]
"""

from pathlib import Path
from typing import TYPE_CHECKING, Callable, Generator, List, Optional, Tuple

import polars as pl
from rich.progress import (
    BarColumn,
    Progress,
    TaskProgressColumn,
    TextColumn,
    TimeRemainingColumn,
)

from cvec.core.config import Config, get_config

# Check for optional dependencies
_SEMANTIC_AVAILABLE = False
_SEMANTIC_IMPORT_ERROR: Optional[str] = None

try:
    import numpy as np
    from fastembed import TextEmbedding

    _SEMANTIC_AVAILABLE = True
except ImportError as e:
    _SEMANTIC_IMPORT_ERROR = str(e)
    # Create placeholder for type hints
    if TYPE_CHECKING:
        import numpy as np
        from fastembed import TextEmbedding


class SemanticDependencyError(Exception):
    """Raised when semantic search dependencies are not installed."""

    def __init__(self, operation: str = "semantic search"):
        self.operation = operation
        super().__init__(
            f"Cannot perform {operation}: fastembed is not installed.\n"
            f"Install with: pip install cvec[semantic]\n"
            f"Or with uv: uv pip install cvec[semantic]"
        )


def is_semantic_available() -> bool:
    """Check if semantic search dependencies are installed.

    Returns:
        True if fastembed and numpy are available.
    """
    return _SEMANTIC_AVAILABLE


def get_semantic_import_error() -> Optional[str]:
    """Get the import error message if semantic dependencies failed to load.

    Returns:
        Error message string or None if dependencies are available.
    """
    return _SEMANTIC_IMPORT_ERROR


# Model configuration
# fastembed uses BAAI/bge-small-en-v1.5 equivalent to all-MiniLM-L6-v2
DEFAULT_MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
EMBEDDING_DIMENSION = 384  # Dimension of all-MiniLM-L6-v2 embeddings
DEFAULT_BATCH_SIZE = 512  # Optimal batch size for CPU processing


class EmbeddingsService:
    """Service for generating and managing CVE embeddings.

    Uses fastembed with the all-MiniLM-L6-v2 model for fast,
    high-quality semantic embeddings suitable for similarity search.
    """

    def __init__(
        self,
        config: Optional[Config] = None,
        model_name: str = DEFAULT_MODEL_NAME,
        quiet: bool = False,
    ):
        """Initialize the embeddings service.

        Args:
            config: Configuration instance. Uses default if not provided.
            model_name: Name of the fastembed model to use.
            quiet: If True, suppress progress output.
        """
        self.config = config or get_config()
        self.model_name = model_name
        self.quiet = quiet
        self._model: Optional["TextEmbedding"] = None

    def _get_model(self) -> "TextEmbedding":
        """Lazily load the fastembed model.

        Raises:
            SemanticDependencyError: If fastembed is not installed.
        """
        if not _SEMANTIC_AVAILABLE:
            raise SemanticDependencyError("embedding generation")

        if self._model is None:
            self._model = TextEmbedding(model_name=self.model_name)
        return self._model

    def _prepare_texts(
        self, cves_df: pl.DataFrame, descriptions_df: pl.DataFrame
    ) -> List[Tuple[str, str]]:
        """Prepare text content for embedding generation.

        Combines CVE title and description for each CVE to create
        meaningful text for semantic embedding.

        Args:
            cves_df: DataFrame with CVE metadata including cna_title.
            descriptions_df: DataFrame with CVE descriptions.

        Returns:
            List of (cve_id, text) tuples.
        """
        # Get English descriptions (preferring CNA source)
        desc_priority = (
            descriptions_df.filter(pl.col("lang") == "en")
            .with_columns(
                pl.when(pl.col("source") == "cna")
                .then(0)
                .otherwise(1)
                .alias("priority")
            )
            .sort(["cve_id", "priority"])
            .group_by("cve_id")
            .first()
        )

        # Join with CVE data
        combined = cves_df.select(["cve_id", "cna_title"]).join(
            desc_priority.select(["cve_id", "value"]),
            on="cve_id",
            how="left",
        )

        # Build text for each CVE
        results = []
        for row in combined.iter_rows(named=True):
            cve_id = row["cve_id"]
            title = row.get("cna_title") or ""
            description = row.get("value") or ""

            # Combine title and description
            if title and description:
                text = f"{title}. {description}"
            elif title:
                text = title
            elif description:
                text = description
            else:
                # Skip CVEs with no textual content
                text = ""

            if text.strip():
                results.append((cve_id, text))

        return results

    def generate_embeddings(
        self,
        cves_df: pl.DataFrame,
        descriptions_df: pl.DataFrame,
        batch_size: int = DEFAULT_BATCH_SIZE,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> pl.DataFrame:
        """Generate embeddings for CVE data.

        Args:
            cves_df: DataFrame with CVE metadata.
            descriptions_df: DataFrame with CVE descriptions.
            batch_size: Number of texts to process per batch.
            progress_callback: Optional callback function(processed, total) for progress tracking.

        Returns:
            DataFrame with cve_id and embedding columns.
        """
        model = self._get_model()

        # Prepare texts
        cve_texts = self._prepare_texts(cves_df, descriptions_df)

        if not cve_texts:
            # Return empty DataFrame with correct schema
            return pl.DataFrame(
                schema={"cve_id": pl.Utf8, "embedding": pl.List(pl.Float32)}
            )

        cve_ids = [ct[0] for ct in cve_texts]
        texts = [ct[1] for ct in cve_texts]
        total_texts = len(texts)

        if not self.quiet:
            print(f"Generating embeddings for {total_texts} CVEs...")

        # Generate embeddings using fastembed's batch generator
        all_embeddings: List[List[float]] = []

        if self.quiet:
            # Silent processing - fastembed returns a generator
            embeddings_generator = model.embed(
                texts,
                batch_size=batch_size,
            )
            for embedding in embeddings_generator:
                # fastembed returns numpy arrays, normalize for cosine similarity
                emb = np.array(embedding)
                norm = np.linalg.norm(emb)
                if norm > 0:
                    emb = emb / norm
                all_embeddings.append(emb.tolist())
                if progress_callback:
                    progress_callback(len(all_embeddings), total_texts)
        else:
            # Show progress bar
            progress = Progress(
                TextColumn("{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                TimeRemainingColumn(),
            )
            with progress:
                task = progress.add_task("Encoding", total=total_texts)
                embeddings_generator = model.embed(
                    texts,
                    batch_size=batch_size,
                )
                for embedding in embeddings_generator:
                    # fastembed returns numpy arrays, normalize for cosine similarity
                    emb = np.array(embedding)
                    norm = np.linalg.norm(emb)
                    if norm > 0:
                        emb = emb / norm
                    all_embeddings.append(emb.tolist())
                    progress.update(task, advance=1)
                    if progress_callback:
                        progress_callback(len(all_embeddings), total_texts)

        # Create DataFrame
        result_df = pl.DataFrame(
            {
                "cve_id": cve_ids,
                "embedding": all_embeddings,
            }
        )

        return result_df

    def extract_embeddings(
        self,
        output_path: Optional[Path] = None,
        batch_size: int = DEFAULT_BATCH_SIZE,
    ) -> dict:
        """Extract embeddings from existing parquet files.

        Reads CVE and description data from parquet files and generates
        embeddings for all CVEs.

        Args:
            output_path: Path to save embeddings parquet. Uses config default if None.
            batch_size: Number of texts to process per batch.

        Returns:
            Dictionary with extraction statistics.
        """
        output_path = output_path or self.config.cve_embeddings_parquet

        # Load existing parquet data
        cves_path = self.config.cves_parquet
        desc_path = self.config.cve_descriptions_parquet

        if not cves_path.exists():
            raise FileNotFoundError(
                f"CVE data not found at {cves_path}. Run 'cvec db update' or 'cvec db build extract-parquet' first."
            )

        cves_df = pl.read_parquet(cves_path)

        if desc_path.exists():
            descriptions_df = pl.read_parquet(desc_path)
        else:
            # Create empty descriptions DataFrame if not available
            descriptions_df = pl.DataFrame(
                schema={
                    "cve_id": pl.Utf8,
                    "lang": pl.Utf8,
                    "value": pl.Utf8,
                    "source": pl.Utf8,
                }
            )

        # Generate embeddings
        embeddings_df = self.generate_embeddings(
            cves_df, descriptions_df, batch_size=batch_size
        )

        # Save to parquet
        embeddings_df.write_parquet(output_path)

        if not self.quiet:
            print(f"Wrote {len(embeddings_df)} embeddings to {output_path}")

        return {
            "path": output_path,
            "count": len(embeddings_df),
            "model": self.model_name,
            "dimension": EMBEDDING_DIMENSION,
        }

    def encode_query(self, query: str) -> "np.ndarray":
        """Encode a search query to an embedding vector.

        Args:
            query: The search query text.

        Returns:
            Normalized embedding vector as numpy array.
        """
        model = self._get_model()
        # fastembed.embed returns a generator, convert to list and get first
        embeddings = list(model.embed([query]))
        embedding = np.array(embeddings[0])
        # Normalize for cosine similarity
        norm = np.linalg.norm(embedding)
        if norm > 0:
            embedding = embedding / norm
        return embedding

    def search(
        self,
        query: str,
        top_k: int = 100,
        min_similarity: float = 0.0,
    ) -> pl.DataFrame:
        """Search for CVEs semantically similar to the query.

        Args:
            query: The search query text.
            top_k: Maximum number of results to return.
            min_similarity: Minimum cosine similarity threshold (0-1).

        Returns:
            DataFrame with cve_id and similarity_score columns, sorted by similarity.
        """
        embeddings_path = self.config.cve_embeddings_parquet

        if not embeddings_path.exists():
            raise FileNotFoundError(
                f"Embeddings not found at {embeddings_path}. "
                "Run 'cvec db update --embeddings' to download or 'cvec db build extract-embeddings' to generate locally."
            )

        # Load embeddings
        embeddings_df = pl.read_parquet(embeddings_path)

        if len(embeddings_df) == 0:
            return pl.DataFrame(
                schema={"cve_id": pl.Utf8, "similarity_score": pl.Float64}
            )

        # Encode query
        query_embedding = self.encode_query(query)

        # Convert embeddings to numpy for efficient computation
        cve_ids = embeddings_df.get_column("cve_id").to_list()
        embeddings = np.array(embeddings_df.get_column("embedding").to_list())

        # Compute cosine similarities (embeddings are already normalized)
        similarities = np.dot(embeddings, query_embedding)

        # Create results DataFrame
        results_df = pl.DataFrame(
            {
                "cve_id": cve_ids,
                "similarity_score": similarities.tolist(),
            }
        )

        # Filter and sort
        results_df = (
            results_df.filter(pl.col("similarity_score") >= min_similarity)
            .sort("similarity_score", descending=True)
            .head(top_k)
        )

        return results_df

    def has_embeddings(self) -> bool:
        """Check if embeddings file exists.

        Returns:
            True if embeddings parquet file exists, False otherwise.
        """
        return self.config.cve_embeddings_parquet.exists()

    def get_stats(self) -> Optional[dict]:
        """Get statistics about stored embeddings.

        Returns:
            Dictionary with embedding statistics, or None if no embeddings exist.
        """
        if not self.has_embeddings():
            return None

        embeddings_df = pl.read_parquet(self.config.cve_embeddings_parquet)

        return {
            "count": len(embeddings_df),
            "model": self.model_name,
            "dimension": EMBEDDING_DIMENSION,
            "path": str(self.config.cve_embeddings_parquet),
        }
