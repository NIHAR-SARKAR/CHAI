"""Configuration loader — merges config.yaml + .security.yml into typed objects."""
import os
import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ServerConfig:
    name: str = "chai-mcp-security"
    version: str = "2.0.0"
    transport: str = "stdio"
    sse_port: int = 9010
    log_level: str = "info"


@dataclass
class PathsConfig:
    kb_path: str = "/opt/kb"
    session_db: str = "/opt/sessions/sessions.db"
    sandbox_user: str = "pentester"
    firejail_profile: str = "/etc/firejail/pentest.profile"
    audit_log_path: str = "/opt/logs/audit.log"
    reports_path: str = "/opt/sessions/reports"
    plugins_path: str = "/opt/mcp-security-server/plugins/external"


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
    max_phases: int = 4
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
class SecretsConfig:
    azure_openai: dict = field(default_factory=dict)
    openai: dict = field(default_factory=dict)
    anthropic: dict = field(default_factory=dict)
    amazon_bedrock: dict = field(default_factory=dict)
    openrouter: dict = field(default_factory=dict)
    huggingface: dict = field(default_factory=dict)
    burp_api: dict = field(default_factory=dict)


@dataclass
class Config:
    server: ServerConfig = field(default_factory=lambda: ServerConfig())
    paths: PathsConfig = field(default_factory=lambda: PathsConfig())
    sandbox: SandboxConfig = field(default_factory=lambda: SandboxConfig())
    llm: LLMConfig = field(default_factory=lambda: LLMConfig())
    ai_planner: AIPlannerConfig = field(default_factory=lambda: AIPlannerConfig())
    plugins: PluginsConfig = field(default_factory=lambda: PluginsConfig())
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
        )

    return config
