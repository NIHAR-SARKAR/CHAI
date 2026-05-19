"""
Auto-discovers and loads plugin modules from:
1. plugins/bundled/  (shipped with the server)
2. config.paths.plugins_path (external drop-in directory)

To add a plugin: drop a .py file with a PentestPlugin subclass
into the plugins/external/ directory and restart the server.
No other changes required.
"""
import importlib.util
import inspect
import logging
from pathlib import Path
from plugins.plugin_base import PentestPlugin

logger = logging.getLogger(__name__)


class PluginLoader:
    def __init__(self, config, process_controller, safety_policy, session_manager):
        self._config = config
        self._pc = process_controller
        self._sp = safety_policy
        self._sm = session_manager
        self._plugins: dict[str, PentestPlugin] = {}

    async def load_all(self):
        """Load bundled plugins (if enabled) then external plugins."""
        if not self._config.plugins.enabled:
            logger.info("Plugin system disabled in config")
            return

        # Bundled plugins
        bundled_path = Path(__file__).parent / "bundled"
        await self._load_from_directory(bundled_path, bundled=True)

        # External drop-in plugins
        external_path = Path(self._config.paths.plugins_path)
        if external_path.exists():
            await self._load_from_directory(external_path, bundled=False)
        else:
            logger.info(f"External plugins path not found: {external_path}")

        logger.info(f"Loaded {len(self._plugins)} plugin(s): {list(self._plugins.keys())}")

    async def _load_from_directory(self, directory: Path, bundled: bool):
        for py_file in directory.glob("*.py"):
            if py_file.name.startswith("_"):
                continue
            try:
                spec = importlib.util.spec_from_file_location(py_file.stem, py_file)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                for _, cls in inspect.getmembers(module, inspect.isclass):
                    if (issubclass(cls, PentestPlugin)
                            and cls is not PentestPlugin
                            and not inspect.isabstract(cls)):
                        instance = cls()

                        # Check config enable/disable for bundled plugins
                        if bundled:
                            plugin_name = instance.metadata.name
                            bundled_cfg = getattr(self._config.plugins.bundled, plugin_name, None)
                            if bundled_cfg is False:
                                logger.debug(f"Plugin '{plugin_name}' disabled in config")
                                continue

                        if await instance.is_available():
                            self._plugins[instance.metadata.name] = instance
                            logger.info(f"Loaded plugin: {instance.metadata.display_name}")
                        else:
                            logger.warning(
                                f"Plugin '{instance.metadata.name}' skipped: "
                                f"binary '{instance.metadata.requires_binary}' not found"
                            )
            except Exception as e:
                logger.error(f"Failed to load plugin from {py_file}: {e}")

    def get(self, name: str) -> PentestPlugin | None:
        return self._plugins.get(name)

    def list_plugins(self) -> list[dict]:
        return [
            {
                "name": p.metadata.name,
                "display_name": p.metadata.display_name,
                "version": p.metadata.version,
                "tier": p.metadata.tier,
                "tags": p.metadata.tags,
            }
            for p in self._plugins.values()
        ]
