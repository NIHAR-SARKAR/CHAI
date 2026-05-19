"""Playbook loader with section extraction regex."""
import re
import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

# Regex patterns for playbook section extraction
SECTION_PATTERNS = {
    "recon": re.compile(r"(?i)#+\s*recon(?:naissance)?|recon(?:naissance)?\s*phase", re.IGNORECASE),
    "scan": re.compile(r"(?i)#+\s*scan(?:ning)?|scan(?:ning)?\s*phase", re.IGNORECASE),
    "exploit": re.compile(r"(?i)#+\s*exploit(?:ation)?|exploit(?:ation)?\s*phase", re.IGNORECASE),
    "post_exploit": re.compile(r"(?i)#+\s*post[-_]?exploit|post[-_]?exploit(?:ation)?\s*phase", re.IGNORECASE),
    "report": re.compile(r"(?i)#+\s*report(?:ing)?|report(?:ing)?\s*phase", re.IGNORECASE),
}

# Pattern to extract tool references
TOOL_PATTERN = re.compile(
    r"(?:run|use|execute|call)\s+["']?([a-zA-Z0-9_-]+)["']?|"
    r"([a-zA-Z0-9_-]+)\s+(?:--[a-z-]+|-[a-z]+)",
    re.IGNORECASE
)


class PlaybookLoader:
    def __init__(self, kb_path: str):
        self._kb_path = Path(kb_path)
        self._kb_path.mkdir(parents=True, exist_ok=True)
        self._playbooks: Dict[str, Dict[str, Any]] = {}

    async def load_playbook(self, playbook_path: str) -> Dict[str, Any]:
        """Load a playbook from file."""
        path = Path(playbook_path)
        if not path.exists():
            raise FileNotFoundError(f"Playbook not found: {playbook_path}")

        content = path.read_text()

        # Extract sections
        sections = self._extract_sections(content)

        # Extract metadata from frontmatter or headers
        metadata = self._extract_metadata(content)

        playbook = {
            "id": path.stem,
            "name": metadata.get("name", path.stem),
            "test_type": metadata.get("test_type", "web_app"),
            "description": metadata.get("description", ""),
            "sections": sections,
            "tools_referenced": self._extract_tools(content),
            "raw_content": content,
        }

        self._playbooks[playbook["id"]] = playbook
        logger.info(f"Loaded playbook: {playbook['name']}")
        return playbook

    def _extract_sections(self, content: str) -> Dict[str, str]:
        """Extract sections from playbook content using regex."""
        sections = {}
        lines = content.split("\n")
        current_section = None
        current_content = []

        for line in lines:
            # Check if line starts a new section
            for section_name, pattern in SECTION_PATTERNS.items():
                if pattern.search(line):
                    # Save previous section
                    if current_section:
                        sections[current_section] = "\n".join(current_content).strip()
                    current_section = section_name
                    current_content = []
                    break
            else:
                if current_section:
                    current_content.append(line)

        # Save last section
        if current_section and current_content:
            sections[current_section] = "\n".join(current_content).strip()

        return sections

    def _extract_metadata(self, content: str) -> Dict[str, Any]:
        """Extract YAML frontmatter or header metadata."""
        metadata = {}

        # Try YAML frontmatter
        frontmatter_match = re.match(r"^---\n(.*?)\n---", content, re.DOTALL)
        if frontmatter_match:
            try:
                import yaml
                metadata = yaml.safe_load(frontmatter_match.group(1)) or {}
            except ImportError:
                pass

        # Try to extract from first H1
        h1_match = re.search(r"^#\s+(.+)$", content, re.MULTILINE)
        if h1_match and "name" not in metadata:
            metadata["name"] = h1_match.group(1).strip()

        return metadata

    def _extract_tools(self, content: str) -> List[str]:
        """Extract tool references from playbook content."""
        tools = set()
        for match in TOOL_PATTERN.finditer(content):
            tool = match.group(1) or match.group(2)
            if tool:
                tools.add(tool.lower())
        return sorted(list(tools))

    def get_playbook(self, playbook_id: str) -> Optional[Dict[str, Any]]:
        """Get a loaded playbook by ID."""
        return self._playbooks.get(playbook_id)

    def list_playbooks(self) -> List[Dict[str, str]]:
        """List all loaded playbooks."""
        return [
            {"id": k, "name": v["name"], "test_type": v["test_type"]}
            for k, v in self._playbooks.items()
        ]
