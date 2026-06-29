"""Vector search with sqlite-vec for embeddings or BM25 keyword fallback."""
import aiosqlite
import json
import logging
import math
import re
from collections import Counter
from pathlib import Path
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


def _tokenize(text: str) -> List[str]:
    """Simple tokenizer: lowercase, split on non-alphanumeric."""
    return re.findall(r"[a-z0-9]{2,}", text.lower())


def _bm25_score(
    query_tokens: List[str],
    doc_tokens: List[str],
    doc_freqs: Dict[str, int],
    total_docs: int,
    avg_dl: float,
    k1: float = 1.5,
    b: float = 0.75,
) -> float:
    """Compute BM25 score for a document against a query."""
    score = 0.0
    doc_len = len(doc_tokens)
    doc_counter = Counter(doc_tokens)
    for qt in query_tokens:
        if qt not in doc_counter:
            continue
        tf = doc_counter[qt]
        df = doc_freqs.get(qt, 0)
        if df == 0:
            continue
        idf = math.log((total_docs - df + 0.5) / (df + 0.5) + 1.0)
        numerator = tf * (k1 + 1)
        denominator = tf + k1 * (1 - b + b * doc_len / avg_dl) if avg_dl > 0 else tf + k1
        score += idf * numerator / denominator
    return score


class VectorSearch:
    def __init__(self, db_path: str):
        self._db_path = db_path
        self._initialized = False
        self._use_vec = False
        self._embedding_model = None
        self._embedding_dim = 384

    async def initialize(self):
        """Initialize vector search. Try sqlite-vec + sentence-transformers, fallback to BM25."""
        try:
            import sqlite_vec
            self._use_vec = True
            logger.info("sqlite-vec available for vector search")
        except ImportError:
            logger.info("sqlite-vec not available, will use BM25 fallback")

        try:
            from sentence_transformers import SentenceTransformer
            self._embedding_model = SentenceTransformer("all-MiniLM-L6-v2")
            self._embedding_dim = self._embedding_model.get_sentence_embedding_dimension()
            logger.info(f"Embedding model loaded: all-MiniLM-L6-v2 (dim={self._embedding_dim})")
        except (ImportError, Exception) as e:
            self._embedding_model = None
            logger.info(f"Embedding model not available: {e}, using BM25 only")

        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        await self._init_schema()
        self._initialized = True

    async def _init_schema(self):
        """Create database tables for search index."""
        async with aiosqlite.connect(self._db_path) as db:
            await db.executescript("""
                CREATE TABLE IF NOT EXISTS documents (
                    doc_id TEXT PRIMARY KEY,
                    content TEXT NOT NULL,
                    metadata TEXT DEFAULT '{}',
                    tokens TEXT DEFAULT '[]',
                    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
                );

                CREATE TABLE IF NOT EXISTS doc_stats (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_documents_id ON documents(doc_id);
            """)
            await db.commit()

        if self._use_vec and self._embedding_model:
            try:
                import sqlite_vec
                async with aiosqlite.connect(self._db_path) as db:
                    db.enable_load_extension(True)
                    sqlite_vec.load(db)
                    await db.execute(
                        f"CREATE VIRTUAL TABLE IF NOT EXISTS vec_documents USING vec0("
                        f"doc_id TEXT PRIMARY KEY, embedding float[{self._embedding_dim}])"
                    )
                    await db.commit()
                logger.info("Vector embedding table created")
            except Exception as e:
                logger.warning(f"Could not create vector table: {e}")
                self._use_vec = False

    async def index_document(self, doc_id: str, content: str, metadata: Dict[str, Any] = None):
        """Index a document for search with both vector embedding and token data."""
        tokens = _tokenize(content)
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                """INSERT OR REPLACE INTO documents (doc_id, content, metadata, tokens)
                   VALUES (?, ?, ?, ?)""",
                (doc_id, content, json.dumps(metadata or {}), json.dumps(tokens)),
            )
            await db.commit()

        if self._use_vec and self._embedding_model:
            try:
                embedding = self._embedding_model.encode(content, normalize_embeddings=True)
                import sqlite_vec
                import struct
                async with aiosqlite.connect(self._db_path) as db:
                    db.enable_load_extension(True)
                    sqlite_vec.load(db)
                    vec_bytes = struct.pack(f"{len(embedding)}f", *embedding)
                    await db.execute(
                        "INSERT OR REPLACE INTO vec_documents (doc_id, embedding) VALUES (?, ?)",
                        (doc_id, vec_bytes),
                    )
                    await db.commit()
            except Exception as e:
                logger.debug(f"Vector indexing failed for {doc_id}: {e}")

        await self._update_stats()
        logger.debug(f"Indexed document: {doc_id}")

    async def _update_stats(self):
        """Update document statistics for BM25 scoring."""
        async with aiosqlite.connect(self._db_path) as db:
            cursor = await db.execute("SELECT COUNT(*) FROM documents")
            row = await cursor.fetchone()
            total_docs = row[0]

            cursor = await db.execute("SELECT tokens FROM documents")
            rows = await cursor.fetchall()
            total_tokens = 0
            doc_freqs: Dict[str, int] = Counter()
            for (tokens_json,) in rows:
                doc_tokens = json.loads(tokens_json)
                total_tokens += len(doc_tokens)
                for t in set(doc_tokens):
                    doc_freqs[t] += 1

            avg_dl = total_tokens / total_docs if total_docs > 0 else 0

            await db.execute(
                "INSERT OR REPLACE INTO doc_stats (key, value) VALUES (?, ?)",
                ("total_docs", str(total_docs)),
            )
            await db.execute(
                "INSERT OR REPLACE INTO doc_stats (key, value) VALUES (?, ?)",
                ("avg_dl", str(avg_dl)),
            )
            await db.execute(
                "INSERT OR REPLACE INTO doc_stats (key, value) VALUES (?, ?)",
                ("doc_freqs", json.dumps(dict(doc_freqs))),
            )
            await db.commit()

    async def search(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """Search for relevant documents using vector similarity or BM25 fallback."""
        if self._use_vec and self._embedding_model:
            results = await self._vector_search(query, top_k)
            if results:
                return results
        return await self.keyword_search(query, top_k)

    async def _vector_search(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """Perform vector similarity search using sqlite-vec."""
        try:
            import sqlite_vec
            import struct

            query_embedding = self._embedding_model.encode(query, normalize_embeddings=True)
            query_vec = struct.pack(f"{len(query_embedding)}f", *query_embedding)

            async with aiosqlite.connect(self._db_path) as db:
                db.enable_load_extension(True)
                sqlite_vec.load(db)
                cursor = await db.execute(
                    "SELECT doc_id, distance FROM vec_documents WHERE embedding MATCH ? ORDER BY distance LIMIT ?",
                    (query_vec, top_k),
                )
                vec_results = await cursor.fetchall()

            results = []
            for doc_id, distance in vec_results:
                doc = await self._get_document(doc_id)
                if doc:
                    doc["score"] = 1.0 - distance
                    results.append(doc)
            return results
        except Exception as e:
            logger.debug(f"Vector search failed: {e}")
            return []

    async def keyword_search(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """BM25 keyword search."""
        query_tokens = _tokenize(query)
        if not query_tokens:
            return []

        async with aiosqlite.connect(self._db_path) as db:
            cursor = await db.execute("SELECT value FROM doc_stats WHERE key = 'total_docs'")
            row = await cursor.fetchone()
            total_docs = int(row[0]) if row else 0

            cursor = await db.execute("SELECT value FROM doc_stats WHERE key = 'avg_dl'")
            row = await cursor.fetchone()
            avg_dl = float(row[0]) if row else 0.0

            cursor = await db.execute("SELECT value FROM doc_stats WHERE key = 'doc_freqs'")
            row = await cursor.fetchone()
            doc_freqs = json.loads(row[0]) if row else {}

            cursor = await db.execute("SELECT doc_id, content, metadata, tokens FROM documents")
            rows = await cursor.fetchall()

        scored = []
        for doc_id, content, metadata_json, tokens_json in rows:
            doc_tokens = json.loads(tokens_json)
            score = _bm25_score(query_tokens, doc_tokens, doc_freqs, total_docs, avg_dl)
            if score > 0:
                scored.append({
                    "doc_id": doc_id,
                    "content": content[:500],
                    "metadata": json.loads(metadata_json),
                    "score": round(score, 4),
                })

        scored.sort(key=lambda x: x["score"], reverse=True)
        return scored[:top_k]

    async def _get_document(self, doc_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single document by ID."""
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT doc_id, content, metadata FROM documents WHERE doc_id = ?",
                (doc_id,),
            )
            row = await cursor.fetchone()
            if row:
                return {
                    "doc_id": row["doc_id"],
                    "content": row["content"][:500],
                    "metadata": json.loads(row["metadata"]),
                }
            return None
