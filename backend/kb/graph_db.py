"""Knowledge graph database with recursive CTE attack chain queries."""
import aiosqlite
import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


class GraphDB:
    def __init__(self, db_path: str):
        self._db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    async def initialize(self):
        """Initialize graph database with schema and seed data."""
        init_sql_path = Path(__file__).parent.parent / "data" / "init_graph.sql"
        async with aiosqlite.connect(self._db_path) as db:
            with open(init_sql_path, "r") as f:
                await db.executescript(f.read())
            await db.commit()
        logger.info("Graph database initialized")

    async def get_technique(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """Get a technique by ID."""
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM techniques WHERE id = ?", (technique_id,)
            )
            row = await cursor.fetchone()
            if row:
                return {
                    "id": row["id"],
                    "name": row["name"],
                    "category": row["category"],
                    "description": row["description"],
                    "prerequisites": json.loads(row["prerequisites"]),
                    "indicators": json.loads(row["indicators"]),
                    "mitre_tactic": row["mitre_tactic"],
                    "mitre_technique": row["mitre_technique"],
                    "tier": row["tier"],
                    "tags": json.loads(row["tags"]),
                }
            return None

    async def get_attack_chain(
        self,
        entry_attack: str,
        goal: str = "escalate",
        max_depth: int = 3,
    ) -> List[Dict[str, Any]]:
        """
        Get attack chains using recursive CTE.
        Returns list of possible next techniques from the entry attack.
        """
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row

            # Recursive CTE to find attack chains
            query = """
            WITH RECURSIVE chain AS (
                -- Base case: direct transitions from entry
                SELECT 
                    ac.from_technique,
                    ac.to_technique,
                    ac.condition,
                    ac.probability,
                    1 as depth
                FROM attack_chains ac
                WHERE ac.from_technique = ?

                UNION ALL

                -- Recursive case: follow chains
                SELECT 
                    ac.from_technique,
                    ac.to_technique,
                    ac.condition,
                    ac.probability * c.probability as probability,
                    c.depth + 1
                FROM attack_chains ac
                JOIN chain c ON ac.from_technique = c.to_technique
                WHERE c.depth < ?
            )
            SELECT DISTINCT
                c.to_technique as technique_id,
                t.name,
                t.category,
                t.description,
                t.tier,
                MAX(c.probability) as probability,
                MIN(c.depth) as min_depth
            FROM chain c
            JOIN techniques t ON c.to_technique = t.id
            GROUP BY c.to_technique
            ORDER BY probability DESC, min_depth ASC
            """

            cursor = await db.execute(query, (entry_attack, max_depth))
            rows = await cursor.fetchall()

            return [
                {
                    "technique_id": row["technique_id"],
                    "name": row["name"],
                    "category": row["category"],
                    "description": row["description"],
                    "tier": row["tier"],
                    "probability": row["probability"],
                    "depth": row["min_depth"],
                }
                for row in rows
            ]

    async def get_playbook(self, playbook_id: str) -> Optional[Dict[str, Any]]:
        """Get a playbook by ID."""
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM playbooks WHERE id = ?", (playbook_id,)
            )
            row = await cursor.fetchone()
            if row:
                return {
                    "id": row["id"],
                    "name": row["name"],
                    "test_type": row["test_type"],
                    "description": row["description"],
                    "phases": json.loads(row["phases"]),
                }
            return None

    async def search_techniques(
        self,
        category: Optional[str] = None,
        tier: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Search techniques by filters."""
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row

            query = "SELECT * FROM techniques WHERE 1=1"
            params = []

            if category:
                query += " AND category = ?"
                params.append(category)
            if tier:
                query += " AND tier = ?"
                params.append(tier)

            cursor = await db.execute(query, params)
            rows = await cursor.fetchall()

            results = []
            for row in rows:
                technique = {
                    "id": row["id"],
                    "name": row["name"],
                    "category": row["category"],
                    "description": row["description"],
                    "tier": row["tier"],
                    "tags": json.loads(row["tags"]),
                }
                if tags:
                    technique_tags = set(technique["tags"])
                    if technique_tags.intersection(set(tags)):
                        results.append(technique)
                else:
                    results.append(technique)

            return results

    async def add_technique(self, technique: Dict[str, Any]) -> str:
        """Add a new technique to the graph."""
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                """INSERT OR REPLACE INTO techniques 
                   (id, name, category, description, prerequisites, indicators, 
                    mitre_tactic, mitre_technique, tier, tags)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    technique["id"],
                    technique["name"],
                    technique["category"],
                    technique.get("description", ""),
                    json.dumps(technique.get("prerequisites", [])),
                    json.dumps(technique.get("indicators", [])),
                    technique.get("mitre_tactic", ""),
                    technique.get("mitre_technique", ""),
                    technique.get("tier", "tier1"),
                    json.dumps(technique.get("tags", [])),
                )
            )
            await db.commit()
        return technique["id"]

    async def add_attack_chain(self, from_id: str, to_id: str, condition: str = "", probability: float = 0.5):
        """Add an attack chain relationship."""
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                """INSERT OR REPLACE INTO attack_chains 
                   (from_technique, to_technique, condition, probability)
                   VALUES (?, ?, ?, ?)""",
                (from_id, to_id, condition, probability)
            )
            await db.commit()
