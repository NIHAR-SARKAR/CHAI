"""Tests for kb.vector_search — BM25 keyword search functionality."""
import pytest
import pytest_asyncio
import sys
import os
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from kb.vector_search import VectorSearch, _tokenize, _bm25_score


class TestTokenize:
    def test_simple_text(self):
        tokens = _tokenize("SQL injection vulnerability detected")
        assert "sql" in tokens
        assert "injection" in tokens
        assert "vulnerability" in tokens

    def test_removes_short_tokens(self):
        tokens = _tokenize("a b c test")
        assert "a" not in tokens
        assert "test" in tokens

    def test_lowercase(self):
        tokens = _tokenize("NMAP SQLMAP NUCLEI")
        assert "nmap" in tokens
        assert "sqlmap" in tokens
        assert "nuclei" in tokens

    def test_special_chars_removed(self):
        tokens = _tokenize("test@domain.com/path?query=1")
        assert "test" in tokens or "domain" in tokens


class TestBM25Score:
    def test_matching_query_scores_positive(self):
        query_tokens = ["sql", "injection"]
        doc_tokens = ["sql", "injection", "vulnerability", "detected"]
        doc_freqs = {"sql": 5, "injection": 8, "vulnerability": 3, "detected": 10}
        score = _bm25_score(query_tokens, doc_tokens, doc_freqs, 100, 5.0)
        assert score > 0

    def test_no_match_scores_zero(self):
        query_tokens = ["xss", "reflected"]
        doc_tokens = ["sql", "injection", "vulnerability"]
        doc_freqs = {"sql": 5, "injection": 8, "vulnerability": 3}
        score = _bm25_score(query_tokens, doc_tokens, doc_freqs, 100, 5.0)
        assert score == 0.0

    def test_partial_match_scores_positive(self):
        query_tokens = ["sql", "injection"]
        doc_tokens = ["sql", "authentication", "bypass"]
        doc_freqs = {"sql": 5, "authentication": 10, "bypass": 3}
        score = _bm25_score(query_tokens, doc_tokens, doc_freqs, 100, 5.0)
        assert score > 0


class TestVectorSearch:
    @pytest_asyncio.fixture
    async def search_engine(self):
        db_path = os.path.join(tempfile.mkdtemp(), "test_vectors.db")
        vs = VectorSearch(db_path)
        await vs.initialize()
        yield vs

    @pytest.mark.asyncio
    async def test_index_and_keyword_search(self, search_engine):
        vs = search_engine
        await vs.index_document("doc1", "SQL injection vulnerability in login endpoint", {"category": "injection"})
        await vs.index_document("doc2", "Cross-site scripting reflected in search parameter", {"category": "xss"})
        await vs.index_document("doc3", "Authentication bypass via JWT none algorithm", {"category": "auth"})

        results = await vs.keyword_search("SQL injection")
        assert len(results) > 0
        assert results[0]["doc_id"] == "doc1"

    @pytest.mark.asyncio
    async def test_empty_search(self, search_engine):
        vs = search_engine
        await vs.index_document("doc1", "Test document", {})
        results = await vs.keyword_search("")
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_search_no_results(self, search_engine):
        vs = search_engine
        await vs.index_document("doc1", "Authentication testing", {})
        results = await vs.keyword_search("quantum physics astrophysics")
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_index_document_upsert(self, search_engine):
        vs = search_engine
        await vs.index_document("doc1", "First version", {})
        await vs.index_document("doc1", "Updated version with SQL injection details", {})
        results = await vs.keyword_search("SQL injection")
        assert len(results) > 0
        assert results[0]["doc_id"] == "doc1"

    @pytest.mark.asyncio
    async def test_search_returns_top_k(self, search_engine):
        vs = search_engine
        for i in range(10):
            await vs.index_document(f"doc{i}", f"SQL injection variant {i}", {})
        results = await vs.keyword_search("SQL injection", top_k=3)
        assert len(results) <= 3
