"""Configuration loader — merges config.yaml + .security.yml into typed objects."""
import os
import sys
import tempfile
import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ── Unified temp-directory resolver ─────────────────────────────────────────
def _get_chai_base_dir() -> Path:
    r"""
    Return the unified CHAI working directory.
    Windows: %LOCALAPPDATA%\Temp\.chai  (e.g. C:\Users\...\AppData\Local\Temp\.chai)
    Linux:   /tmp/.chai
    macOS:   /tmp/.chai
    """
    if sys.platform == "win32":
        local_appdata = os.environ.get("LOCALAPPDATA", os.path.expanduser("~\\AppData\\Local"))
        base = Path(local_appdata) / "Temp" / ".chai"
    else:
        base = Path("/tmp") / ".chai"
    base.mkdir(parents=True, exist_ok=True)
    return base


_CHAI_BASE = _get_chai_base_dir()


@dataclass
class ServerConfig:
    name: str = "chai-mcp-security"
    version: str = "2.0.0"
    transport: str = "stdio"
    sse_port: int = 9010
    web_port: int = 8060
    web_enabled: bool = True
    log_level: str = "info"


@dataclass
class PathsConfig:
    kb_path: str = str(_CHAI_BASE / "kb")
    session_db: str = str(_CHAI_BASE / "sessions" / "sessions.db")
    sandbox_user: str = "pentester"
    firejail_profile: str = "/etc/firejail/pentest.profile"
    audit_log_path: str = str(_CHAI_BASE / "logs" / "audit.log")
    reports_path: str = str(_CHAI_BASE / "reports")
    plugins_path: str = str(_CHAI_BASE / "plugins" / "external")


@dataclass
class SandboxConfig:
    max_ram_mb: int = 384
    max_cpu_percent: int = 50
    max_concurrent_jobs: int = 2
    command_timeout: int = 300


@dataclass
class LLMProviderConfig:
    enabled: bool = False
    endpoint: str = ""
    api_base: str = ""
    api_version: str = ""
    model: str = ""
    model_id: str = ""
    region: str = ""
    use_iam_role: bool = False
    active_deployment: str = ""
    deployments: dict = field(default_factory=dict)


@dataclass
class LLMConfig:
    enabled: bool = True
    active_provider: str = "azure_openai"
    fallback_provider: str = ""
    max_tokens: int = 1000
    temperature: float = 0.1
    timeout_seconds: int = 30
    max_retries: int = 2
    azure_openai: LLMProviderConfig = field(default_factory=lambda: LLMProviderConfig())
    openai: LLMProviderConfig = field(default_factory=lambda: LLMProviderConfig())
    anthropic: LLMProviderConfig = field(default_factory=lambda: LLMProviderConfig())
    amazon_bedrock: LLMProviderConfig = field(default_factory=lambda: LLMProviderConfig())
    openrouter: LLMProviderConfig = field(default_factory=lambda: LLMProviderConfig())
    huggingface: LLMProviderConfig = field(default_factory=lambda: LLMProviderConfig())


@dataclass
class AIPlannerConfig:
    max_phases: int = 20
    stop_on_critical: bool = True
    max_digest_tokens: int = 500
    use_graph_prefilter: bool = True
    include_ai_narrative: bool = True


@dataclass
class BundledPluginsConfig:
    feroxbuster: bool = True
    metasploit: bool = False
    burp_api: bool = False


@dataclass
class PluginsConfig:
    enabled: bool = True
    bundled: BundledPluginsConfig = field(default_factory=lambda: BundledPluginsConfig())
    auto_discover: bool = True


@dataclass
class WSLConfig:
    enabled: bool = False
    distro_name: str = "kali-linux"
    username: str = ""
    password: str = ""
    ssh_key_path: str = ""
    os_details: str = ""
    use_ssh: bool = False
    auto_install_missing: bool = True
    mount_path_prefix: str = "/mnt"
    default_shell: str = "bash"


@dataclass
class SecretsConfig:
    azure_openai: dict = field(default_factory=dict)
    openai: dict = field(default_factory=dict)
    anthropic: dict = field(default_factory=dict)
    amazon_bedrock: dict = field(default_factory=dict)
    openrouter: dict = field(default_factory=dict)
    huggingface: dict = field(default_factory=dict)
    burp_api: dict = field(default_factory=dict)
    wsl: dict = field(default_factory=dict)


@dataclass
class Config:
    server: ServerConfig = field(default_factory=lambda: ServerConfig())
    paths: PathsConfig = field(default_factory=lambda: PathsConfig())
    sandbox: SandboxConfig = field(default_factory=lambda: SandboxConfig())
    llm: LLMConfig = field(default_factory=lambda: LLMConfig())
    ai_planner: AIPlannerConfig = field(default_factory=lambda: AIPlannerConfig())
    plugins: PluginsConfig = field(default_factory=lambda: PluginsConfig())
    wsl: WSLConfig = field(default_factory=lambda: WSLConfig())
    secrets: SecretsConfig = field(default_factory=lambda: SecretsConfig())


def _dict_to_dataclass(data: dict, cls):
    """Recursively convert dict to dataclass instance."""
    if not isinstance(data, dict):
        return data

    kwargs = {}
    for key, value in data.items():
        if hasattr(cls, "__dataclass_fields__") and key in cls.__dataclass_fields__:
            field_type = cls.__dataclass_fields__[key].type
            # Handle nested dataclasses
            if hasattr(field_type, "__dataclass_fields__") and isinstance(value, dict):
                kwargs[key] = _dict_to_dataclass(value, field_type)
            else:
                kwargs[key] = value
        else:
            kwargs[key] = value
    return cls(**kwargs)


def load_config(config_path: str = "config.yaml", secrets_path: str = ".security.yml") -> Config:
    """Load and merge configuration from YAML files."""
    # Load main config
    with open(config_path, "r") as f:
        config_data = yaml.safe_load(f)

    # Load secrets
    secrets_data = {}
    if os.path.exists(secrets_path):
        with open(secrets_path, "r") as f:
            secrets_data = yaml.safe_load(f) or {}

    # Build config object
    config = Config()

    if config_data:
        if "server" in config_data:
            config.server = _dict_to_dataclass(config_data["server"], ServerConfig)
        if "paths" in config_data:
            config.paths = _dict_to_dataclass(config_data["paths"], PathsConfig)
            # Fallback to unified temp defaults for any blank path values
            for field_name in ["kb_path", "session_db", "audit_log_path", "reports_path", "plugins_path"]:
                val = getattr(config.paths, field_name, "")
                if not val or str(val).strip() == "":
                    default_path = {
                        "kb_path": str(_CHAI_BASE / "kb"),
                        "session_db": str(_CHAI_BASE / "sessions" / "sessions.db"),
                        "audit_log_path": str(_CHAI_BASE / "logs" / "audit.log"),
                        "reports_path": str(_CHAI_BASE / "reports"),
                        "plugins_path": str(_CHAI_BASE / "plugins" / "external"),
                    }.get(field_name, "")
                    setattr(config.paths, field_name, default_path)
        if "sandbox" in config_data:
            config.sandbox = _dict_to_dataclass(config_data["sandbox"], SandboxConfig)
        if "llm" in config_data:
            config.llm = _dict_to_dataclass(config_data["llm"], LLMConfig)
            # Fix nested provider configs
            for provider_name in ["azure_openai", "openai", "anthropic", "amazon_bedrock", "openrouter", "huggingface"]:
                if provider_name in config_data["llm"]:
                    setattr(config.llm, provider_name, 
                           _dict_to_dataclass(config_data["llm"][provider_name], LLMProviderConfig))
        if "ai_planner" in config_data:
            config.ai_planner = _dict_to_dataclass(config_data["ai_planner"], AIPlannerConfig)
        if "plugins" in config_data:
            config.plugins = _dict_to_dataclass(config_data["plugins"], PluginsConfig)
            if "bundled" in config_data["plugins"]:
                config.plugins.bundled = _dict_to_dataclass(config_data["plugins"]["bundled"], BundledPluginsConfig)
        if "wsl" in config_data:
            config.wsl = _dict_to_dataclass(config_data["wsl"], WSLConfig)

    # Attach secrets
    if secrets_data:
        config.secrets = SecretsConfig(
            azure_openai=secrets_data.get("azure_openai", {}),
            openai=secrets_data.get("openai", {}),
            anthropic=secrets_data.get("anthropic", {}),
            amazon_bedrock=secrets_data.get("amazon_bedrock", {}),
            openrouter=secrets_data.get("openrouter", {}),
            huggingface=secrets_data.get("huggingface", {}),
            burp_api=secrets_data.get("burp_api", {}),
            wsl=secrets_data.get("wsl", {}),
        )
        # Merge WSL secrets (password, ssh_key_path) into config.wsl if present
        wsl_secrets = secrets_data.get("wsl", {})
        if wsl_secrets:
            if "password" in wsl_secrets and not config.wsl.password:
                config.wsl.password = wsl_secrets["password"]
            if "ssh_key_path" in wsl_secrets and not config.wsl.ssh_key_path:
                config.wsl.ssh_key_path = wsl_secrets["ssh_key_path"]
            if "username" in wsl_secrets and not config.wsl.username:
                config.wsl.username = wsl_secrets["username"]

    return config
