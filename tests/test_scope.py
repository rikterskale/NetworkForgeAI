from networkforgeai.core.scope import ScopePolicy


def test_scope_accepts_cidr_member_and_rejects_external_ip():
    policy = ScopePolicy(["192.168.10.0/24"])
    assert policy.contains("192.168.10.42")
    assert not policy.contains("192.168.11.42")


def test_scope_accepts_subdomains_and_exclusions():
    policy = ScopePolicy(["example.com"], ["admin.example.com"])
    assert policy.contains("https://www.example.com/login")
    assert not policy.contains("admin.example.com")


def test_empty_scope_denies_by_default():
    assert not ScopePolicy([]).contains("example.com")

