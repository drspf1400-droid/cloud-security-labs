import importlib.util
from pathlib import Path


MODULE_PATH = Path("modules/prioritize.py")
spec = importlib.util.spec_from_file_location("prioritize", MODULE_PATH)
prioritize = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prioritize)


def base_asset():
    return {
        "internet_exposed": None,
        "business_criticality": "unknown",
        "environment": "unknown",
    }


def test_unknown_context_uses_baseline_only():
    finding = {
        "finding_id": "TEST-001",
        "baseline_severity": "high",
        "category": "generic",
        "evidence": {
            "type": "command_output",
            "source": "test",
            "key": "value",
            "observed_value": "ok",
        },
    }

    result = prioritize.prioritize_finding(
        finding,
        base_asset()
    )

    assert result["score"] == 4
    assert result["reasons"] == [
        "baseline_severity=high"
    ]


def test_ssh_root_login_adds_evidence_modifier():
    finding = {
        "finding_id": "SSH-002",
        "baseline_severity": "high",
        "category": "ssh",
        "evidence": {
            "type": "configuration",
            "source": "/etc/ssh/sshd_config",
            "key": "PermitRootLogin",
            "observed_value": "without-password",
        },
    }

    result = prioritize.prioritize_finding(
        finding,
        base_asset()
    )

    assert result["score"] == 5
    assert "ssh_root_login_permitted=true" in result["reasons"]


def test_ssh_password_authentication_adds_modifier():
    finding = {
        "finding_id": "SSH-001",
        "baseline_severity": "medium",
        "category": "ssh",
        "evidence": {
            "type": "configuration",
            "source": "/etc/ssh/sshd_config",
            "key": "PasswordAuthentication",
            "observed_value": "yes",
        },
    }

    result = prioritize.prioritize_finding(
        finding,
        base_asset()
    )

    assert result["score"] == 4
    assert "ssh_password_authentication=true" in result["reasons"]


def test_inactive_firewall_adds_modifier():
    finding = {
        "finding_id": "FW-001",
        "baseline_severity": "high",
        "category": "firewall",
        "evidence": {
            "type": "command_output",
            "source": "ufw status",
            "key": "status",
            "observed_value": "inactive",
        },
    }

    result = prioritize.prioritize_finding(
        finding,
        base_asset()
    )

    assert result["score"] == 5
    assert "host_firewall_inactive=true" in result["reasons"]


def test_socket_all_interfaces_is_not_internet_exposure():
    finding = {
        "finding_id": "NET-8080",
        "baseline_severity": "medium",
        "category": "network",
        "evidence": {
            "type": "socket",
            "source": "ss -lntupH",
            "protocol": "tcp",
            "bind_address": "0.0.0.0",
            "port": 8080,
            "process": "python3",
            "internet_exposed": "unknown",
        },
    }

    result = prioritize.prioritize_finding(
        finding,
        base_asset()
    )

    assert result["score"] == 4
    assert "socket_bound_all_interfaces=true" in result["reasons"]
    assert "socket_internet_exposed=true" not in result["reasons"]


def test_unconfirmed_updates_do_not_add_modifier():
    finding = {
        "finding_id": "UPD-001",
        "baseline_severity": "medium",
        "category": "updates",
        "evidence": {
            "type": "package_inventory",
            "source": "apt list --upgradable",
            "package_manager": "apt",
            "update_count": 10,
            "security_updates_confirmed": False,
        },
    }

    result = prioritize.prioritize_finding(
        finding,
        base_asset()
    )

    assert result["score"] == 3
    assert "security_updates_confirmed=true" not in result["reasons"]


def test_score_is_capped_at_eight():
    finding = {
        "finding_id": "TEST-CAP",
        "baseline_severity": "critical",
        "category": "network",
        "evidence": {
            "type": "socket",
            "source": "ss -lntupH",
            "protocol": "tcp",
            "bind_address": "0.0.0.0",
            "port": 443,
            "process": "service",
            "internet_exposed": True,
        },
    }

    asset = {
        "internet_exposed": True,
        "business_criticality": "critical",
        "environment": "production",
    }

    result = prioritize.prioritize_finding(
        finding,
        asset
    )

    assert result["score"] == 8


def test_engine_version_is_v2():
    finding = {
        "finding_id": "TEST-ENGINE",
        "baseline_severity": "low",
        "category": "generic",
        "evidence": {
            "type": "command_output",
            "source": "test",
            "key": "value",
            "observed_value": "ok",
        },
    }

    result = prioritize.prioritize_finding(
        finding,
        base_asset()
    )

    assert result["engine"]["name"] == \
        "deterministic-context-baseline"
    assert result["engine"]["version"] == "2.0"
