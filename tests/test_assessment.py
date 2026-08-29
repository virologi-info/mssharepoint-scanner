import importlib.util
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "sharepoint-cve-scanner.py"
spec = importlib.util.spec_from_file_location("sharepoint_scanner", MODULE_PATH)
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)


def test_unknown_build_never_defaults_to_subscription_edition():
    assert scanner.detect_edition("16.0.25000.1") is None
    results = scanner.check_build("16.0.25000.1")
    assert all(r["status"] == "UNKNOWN" for r in results)
    assert all(r["vulnerable"] is None for r in results)


def test_invalid_build_is_unknown():
    results = scanner.check_build("not-a-build")
    assert all(r["status"] == "UNKNOWN" for r in results)


def test_known_edition_compares_versions():
    results = scanner.check_build("16.0.5560.1000", "Enterprise 2016")
    assert any(r["status"] == "VULNERABLE" for r in results)


def test_discovery_scope_is_bounded():
    try:
        scanner.expand_targets(["10.0.0.0/8"])
    except ValueError:
        pass
    else:
        raise AssertionError("large CIDR should be rejected")


def test_remote_url_requires_explicit_http_scheme():
    try:
        scanner.normalize_base_url("sharepoint.example.com")
    except ValueError:
        pass
    else:
        raise AssertionError("scheme-less URL should be rejected")
