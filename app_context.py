"""Application context singleton.
Holds all initialized objects for easy access across the application.
"""
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


class AppContext:
    """Singleton application context."""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def initialize(
        self,
        config,
        provider,
        session_manager,
        process_controller,
        safety_policy,
        audit_logger,
        graph_db,
        playbook_loader,
        plugin_loader,
        tools: Dict[str, Any],
    ):
        """Initialize the application context."""
        self.config = config
        self.provider = provider
        self.session_manager = session_manager
        self.process_controller = process_controller
        self.safety_policy = safety_policy
        self.audit_logger = audit_logger
        self.graph_db = graph_db
        self.playbook_loader = playbook_loader
        self.plugin_loader = plugin_loader
        self.tools = tools
        self._initialized = True
        logger.info("Application context initialized")

    @property
    def is_initialized(self) -> bool:
        return self._initialized


def get_context() -> AppContext:
    """Get the application context singleton."""
    return AppContext()
