"""Unit tests for the embeddings service."""

from unittest.mock import MagicMock, patch
import numpy as np
import polars as pl
import pytest

from cvec.services.embeddings import (
    EmbeddingsService,
    DEFAULT_MODEL_NAME,
    EMBEDDING_DIMENSION,
    DEFAULT_BATCH_SIZE,
)


class TestEmbeddingsServiceInit:
    """Tests for EmbeddingsService initialization."""

    def test_init_default_config(self):
        """Service should initialize with default config."""
        service = EmbeddingsService()
        assert service.config is not None
        assert service.model_name == DEFAULT_MODEL_NAME
        assert service.quiet is False
        assert service._model is None  # Model not loaded until needed

    def test_init_custom_model(self):
        """Service should accept custom model name."""
        service = EmbeddingsService(model_name="custom-model")
        assert service.model_name == "custom-model"

    def test_init_quiet_mode(self):
        """Service should support quiet mode."""
        service = EmbeddingsService(quiet=True)
        assert service.quiet is True


class TestPrepareTexts:
    """Tests for text preparation from CVE data."""

    def test_prepare_texts_with_title_and_description(self):
        """Should combine title and description."""
        cves_df = pl.DataFrame(
            {
                "cve_id": ["CVE-2024-1234"],
                "cna_title": ["Test vulnerability"],
            }
        )
        descriptions_df = pl.DataFrame(
            {
                "cve_id": ["CVE-2024-1234"],
                "lang": ["en"],
                "value": ["A buffer overflow vulnerability."],
                "source": ["cna"],
            }
        )

        service = EmbeddingsService(quiet=True)
        texts = service._prepare_texts(cves_df, descriptions_df)

        assert len(texts) == 1
        assert texts[0][0] == "CVE-2024-1234"
        assert "Test vulnerability" in texts[0][1]
        assert "buffer overflow" in texts[0][1]

    def test_prepare_texts_with_title_only(self):
        """Should use title when description is missing."""
        cves_df = pl.DataFrame(
            {
                "cve_id": ["CVE-2024-1234"],
                "cna_title": ["Test vulnerability"],
            }
        )
        descriptions_df = pl.DataFrame(
            schema={
                "cve_id": pl.Utf8,
                "lang": pl.Utf8,
                "value": pl.Utf8,
                "source": pl.Utf8,
            }
        )

        service = EmbeddingsService(quiet=True)
        texts = service._prepare_texts(cves_df, descriptions_df)

        assert len(texts) == 1
        assert texts[0][1] == "Test vulnerability"

    def test_prepare_texts_with_description_only(self):
        """Should use description when title is missing."""
        cves_df = pl.DataFrame(
            {
                "cve_id": ["CVE-2024-1234"],
                "cna_title": [None],
            }
        )
        descriptions_df = pl.DataFrame(
            {
                "cve_id": ["CVE-2024-1234"],
                "lang": ["en"],
                "value": ["A buffer overflow vulnerability."],
                "source": ["cna"],
            }
        )

        service = EmbeddingsService(quiet=True)
        texts = service._prepare_texts(cves_df, descriptions_df)

        assert len(texts) == 1
        assert texts[0][1] == "A buffer overflow vulnerability."

    def test_prepare_texts_skips_empty_content(self):
        """Should skip CVEs with no textual content."""
        cves_df = pl.DataFrame(
            {
                "cve_id": ["CVE-2024-1234", "CVE-2024-5678"],
                "cna_title": [None, "Has title"],
            }
        )
        descriptions_df = pl.DataFrame(
            {
                "cve_id": ["CVE-2024-5678"],
                "lang": ["en"],
                "value": ["Has description"],
                "source": ["cna"],
            }
        )

        service = EmbeddingsService(quiet=True)
        texts = service._prepare_texts(cves_df, descriptions_df)

        # Only one CVE should have text
        assert len(texts) == 1
        assert texts[0][0] == "CVE-2024-5678"

    def test_prepare_texts_prefers_cna_source(self):
        """Should prefer CNA descriptions over ADP."""
        cves_df = pl.DataFrame(
            {
                "cve_id": ["CVE-2024-1234"],
                "cna_title": ["Test"],
            }
        )
        descriptions_df = pl.DataFrame(
            {
                "cve_id": ["CVE-2024-1234", "CVE-2024-1234"],
                "lang": ["en", "en"],
                "value": ["CNA description", "ADP description"],
                "source": ["cna", "adp:CISA"],
            }
        )

        service = EmbeddingsService(quiet=True)
        texts = service._prepare_texts(cves_df, descriptions_df)

        assert len(texts) == 1
        assert "CNA description" in texts[0][1]
        assert "ADP description" not in texts[0][1]


class TestGenerateEmbeddings:
    """Tests for embedding generation."""

    @patch("cvec.services.embeddings.EmbeddingsService._get_model")
    def test_generate_embeddings_basic(self, mock_get_model):
        """Should generate embeddings for CVE data."""
        # Mock the model - fastembed's embed returns a generator
        mock_model = MagicMock()
        # Create a normalized embedding
        mock_embedding = np.array([0.1] * EMBEDDING_DIMENSION)
        mock_embedding = mock_embedding / np.linalg.norm(mock_embedding)
        mock_model.embed.return_value = iter([mock_embedding])
        mock_get_model.return_value = mock_model

        cves_df = pl.DataFrame(
            {
                "cve_id": ["CVE-2024-1234"],
                "cna_title": ["Test vulnerability"],
            }
        )
        descriptions_df = pl.DataFrame(
            {
                "cve_id": ["CVE-2024-1234"],
                "lang": ["en"],
                "value": ["Test description"],
                "source": ["cna"],
            }
        )

        service = EmbeddingsService(quiet=True)
        result = service.generate_embeddings(cves_df, descriptions_df, batch_size=1)

        assert len(result) == 1
        assert "cve_id" in result.columns
        assert "embedding" in result.columns
        assert result["cve_id"][0] == "CVE-2024-1234"

    @patch("cvec.services.embeddings.EmbeddingsService._get_model")
    def test_generate_embeddings_empty_data(self, mock_get_model):
        """Should handle empty data gracefully."""
        cves_df = pl.DataFrame(schema={"cve_id": pl.Utf8, "cna_title": pl.Utf8})
        descriptions_df = pl.DataFrame(
            schema={
                "cve_id": pl.Utf8,
                "lang": pl.Utf8,
                "value": pl.Utf8,
                "source": pl.Utf8,
            }
        )

        service = EmbeddingsService(quiet=True)
        result = service.generate_embeddings(cves_df, descriptions_df)

        assert len(result) == 0
        assert "cve_id" in result.columns
        assert "embedding" in result.columns


class TestEncodeQuery:
    """Tests for query encoding."""

    @patch("cvec.services.embeddings.EmbeddingsService._get_model")
    def test_encode_query(self, mock_get_model):
        """Should encode a query string to an embedding."""
        mock_model = MagicMock()
        # fastembed's embed returns a generator
        expected_embedding = np.array([0.1] * EMBEDDING_DIMENSION)
        mock_model.embed.return_value = iter([expected_embedding])
        mock_get_model.return_value = mock_model

        service = EmbeddingsService(quiet=True)
        result = service.encode_query("buffer overflow vulnerability")

        mock_model.embed.assert_called_once()
        assert isinstance(result, np.ndarray)


class TestSearch:
    """Tests for semantic search functionality."""

    def test_search_no_embeddings_file(self, temp_config):
        """Should raise error when embeddings don't exist."""
        service = EmbeddingsService(config=temp_config, quiet=True)

        with pytest.raises(FileNotFoundError):
            service.search("buffer overflow")

    @patch("cvec.services.embeddings.EmbeddingsService._get_model")
    def test_search_with_embeddings(self, mock_get_model, temp_config):
        """Should return similar CVEs when embeddings exist."""
        # Create mock model - fastembed's embed returns a generator
        mock_model = MagicMock()
        query_embedding = np.array([1.0] * EMBEDDING_DIMENSION)
        mock_model.embed.return_value = iter([query_embedding])
        mock_get_model.return_value = mock_model

        # Create embeddings file
        embeddings_data = {
            "cve_id": ["CVE-2024-1234", "CVE-2024-5678"],
            "embedding": [
                [1.0] * EMBEDDING_DIMENSION,  # High similarity (same as query)
                [0.5] * EMBEDDING_DIMENSION,  # Lower similarity
            ],
        }
        embeddings_df = pl.DataFrame(embeddings_data)
        embeddings_df.write_parquet(temp_config.cve_embeddings_parquet)

        service = EmbeddingsService(config=temp_config, quiet=True)
        result = service.search("buffer overflow", top_k=10, min_similarity=0.0)

        assert len(result) == 2
        assert "cve_id" in result.columns
        assert "similarity_score" in result.columns
        # Results should be sorted by similarity
        scores = result["similarity_score"].to_list()
        assert scores[0] >= scores[1]

    @patch("cvec.services.embeddings.EmbeddingsService._get_model")
    def test_search_with_min_similarity(self, mock_get_model, temp_config):
        """Should filter results below min_similarity."""
        # Create mock model - fastembed's embed returns a generator
        mock_model = MagicMock()
        # Create a normalized query vector (unit length)
        query_vec = np.array([1.0] + [0.0] * (EMBEDDING_DIMENSION - 1))
        mock_model.embed.return_value = iter([query_vec])
        mock_get_model.return_value = mock_model

        # Create embeddings file with normalized vectors having different similarities
        # High similarity: aligned with query (similarity ~ 0.8)
        high_sim_vec = np.array([0.8] + [0.6] + [0.0] * (EMBEDDING_DIMENSION - 2))
        high_sim_vec = high_sim_vec / np.linalg.norm(high_sim_vec)  # normalize

        # Low similarity: mostly orthogonal to query (similarity ~ 0.1)
        low_sim_vec = np.array([0.1] + [0.995] + [0.0] * (EMBEDDING_DIMENSION - 2))
        low_sim_vec = low_sim_vec / np.linalg.norm(low_sim_vec)  # normalize

        embeddings_data = {
            "cve_id": ["CVE-HIGH", "CVE-LOW"],
            "embedding": [
                high_sim_vec.tolist(),
                low_sim_vec.tolist(),
            ],
        }
        embeddings_df = pl.DataFrame(embeddings_data)
        embeddings_df.write_parquet(temp_config.cve_embeddings_parquet)

        service = EmbeddingsService(config=temp_config, quiet=True)
        result = service.search("test query", top_k=10, min_similarity=0.5)

        # Only high similarity result should be returned
        assert len(result) == 1
        assert result["cve_id"][0] == "CVE-HIGH"


class TestHasEmbeddings:
    """Tests for embeddings availability check."""

    def test_has_embeddings_false(self, temp_config):
        """Should return False when embeddings don't exist."""
        service = EmbeddingsService(config=temp_config, quiet=True)
        assert service.has_embeddings() is False

    def test_has_embeddings_true(self, temp_config):
        """Should return True when embeddings exist."""
        # Create embeddings file
        embeddings_df = pl.DataFrame(
            {
                "cve_id": ["CVE-2024-1234"],
                "embedding": [[0.1] * EMBEDDING_DIMENSION],
            }
        )
        embeddings_df.write_parquet(temp_config.cve_embeddings_parquet)

        service = EmbeddingsService(config=temp_config, quiet=True)
        assert service.has_embeddings() is True


class TestGetStats:
    """Tests for embeddings statistics."""

    def test_get_stats_no_embeddings(self, temp_config):
        """Should return None when embeddings don't exist."""
        service = EmbeddingsService(config=temp_config, quiet=True)
        assert service.get_stats() is None

    def test_get_stats_with_embeddings(self, temp_config):
        """Should return stats when embeddings exist."""
        # Create embeddings file
        embeddings_df = pl.DataFrame(
            {
                "cve_id": ["CVE-2024-1234", "CVE-2024-5678"],
                "embedding": [[0.1] * EMBEDDING_DIMENSION, [0.2] * EMBEDDING_DIMENSION],
            }
        )
        embeddings_df.write_parquet(temp_config.cve_embeddings_parquet)

        service = EmbeddingsService(config=temp_config, quiet=True)
        stats = service.get_stats()

        assert stats is not None
        assert stats["count"] == 2
        assert stats["model"] == DEFAULT_MODEL_NAME
        assert stats["dimension"] == EMBEDDING_DIMENSION


class TestProgressCallback:
    """Tests for progress callback functionality."""

    @patch("cvec.services.embeddings.EmbeddingsService._get_model")
    def test_progress_callback_called(self, mock_get_model):
        """Should call progress callback during embedding generation."""
        # Mock the model
        mock_model = MagicMock()
        # Create normalized embeddings
        mock_embedding = np.array([0.1] * EMBEDDING_DIMENSION)
        mock_embedding = mock_embedding / np.linalg.norm(mock_embedding)
        # Return 2 embeddings as generator
        mock_model.embed.return_value = iter([mock_embedding, mock_embedding])
        mock_get_model.return_value = mock_model

        cves_df = pl.DataFrame(
            {
                "cve_id": ["CVE-2024-1234", "CVE-2024-5678"],
                "cna_title": ["Test vulnerability 1", "Test vulnerability 2"],
            }
        )
        descriptions_df = pl.DataFrame(
            {
                "cve_id": ["CVE-2024-1234", "CVE-2024-5678"],
                "lang": ["en", "en"],
                "value": ["Test description 1", "Test description 2"],
                "source": ["cna", "cna"],
            }
        )

        # Track progress callback calls
        progress_calls = []

        def track_progress(processed, total):
            progress_calls.append((processed, total))

        service = EmbeddingsService(quiet=True)
        result = service.generate_embeddings(
            cves_df, descriptions_df, batch_size=1, progress_callback=track_progress
        )

        assert len(result) == 2
        # Should have 2 progress calls (one per CVE)
        assert len(progress_calls) == 2
        assert progress_calls[0] == (1, 2)
        assert progress_calls[1] == (2, 2)


# Fixtures


@pytest.fixture
def temp_config():
    """Create a Config pointing to temporary directories."""
    import tempfile
    from pathlib import Path
    from cvec.core.config import Config

    with tempfile.TemporaryDirectory() as tmpdir:
        temp_path = Path(tmpdir)
        (temp_path / "cve_github" / "individual").mkdir(parents=True)

        config = Config(data_dir=temp_path)
        yield config
