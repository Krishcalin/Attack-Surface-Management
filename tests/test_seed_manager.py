"""Tests for the SeedManager (seed parsing/validation/classification). No network."""
from modules.seed_manager import SeedManager


def test_add_domain_normalises_and_validates():
    sm = SeedManager()
    assert sm.add_domain("  Example.COM. ") is True
    assert sm.seeds.domains == ["example.com"]      # lowercased, trailing dot stripped
    assert sm.add_domain("example.com") is True     # dedup
    assert sm.seeds.domains == ["example.com"]
    assert sm.add_domain("not a domain") is False
    assert sm.add_domain("") is False


def test_add_ip_valid_invalid_and_dedup():
    sm = SeedManager()
    assert sm.add_ip("203.0.113.5") is True
    assert sm.add_ip("203.0.113.5") is True         # dedup -> still one
    assert sm.seeds.ips == ["203.0.113.5"]
    assert sm.add_ip("999.1.1.1") is False
    assert sm.add_ip("::1") is True                  # IPv6 ok


def test_add_cidr_and_asn_normalisation():
    sm = SeedManager()
    assert sm.add_cidr("10.0.0.0/24") is True
    assert sm.add_cidr("10.0.0.5/24") is True        # strict=False -> same network, dedup
    assert sm.seeds.cidrs == ["10.0.0.0/24"]
    assert sm.add_asn("AS15169") is True
    assert sm.add_asn("15169") is True               # normalises to AS15169 -> dedup
    assert sm.add_asn("as15169") is True
    assert sm.seeds.asns == ["AS15169"]
    assert sm.add_asn("ASXYZ") is False


def test_try_add_auto_classifies():
    sm = SeedManager()
    sm.parse_targets(["example.com", "1.1.1.1", "10.0.0.0/30", "AS13335", "  "])
    assert sm.seeds.domains == ["example.com"]
    assert sm.seeds.ips == ["1.1.1.1"]
    assert sm.seeds.cidrs == ["10.0.0.0/30"]
    assert sm.seeds.asns == ["AS13335"]


def test_expand_cidr_small_and_cap():
    sm = SeedManager()
    sm.add_cidr("10.0.0.0/30")          # 2 usable hosts
    ips = sm.expand_cidrs()
    assert ips == ["10.0.0.1", "10.0.0.2"]

    big = SeedManager()
    big.add_cidr("10.0.0.0/15")         # 131072 addresses > 65536 cap -> skipped
    assert big.expand_cidrs() == []


def test_load_from_file(tmp_path):
    f = tmp_path / "seeds.txt"
    f.write_text(
        "# comment\n"
        "example.com\n"
        "\n"
        "203.0.113.0/24\n"
        "AS15169\n"
        "8.8.8.8\n",
        encoding="utf-8",
    )
    sm = SeedManager()
    count = sm.load_from_file(str(f))
    assert count == 4
    assert sm.seeds.domains == ["example.com"]
    assert sm.seeds.cidrs == ["203.0.113.0/24"]
    assert sm.seeds.asns == ["AS15169"]
    assert sm.seeds.ips == ["8.8.8.8"]


def test_is_empty_and_summary():
    sm = SeedManager()
    assert sm.seeds.is_empty
    sm.set_org("ACME")
    sm.add_domain("acme.com")
    assert not sm.seeds.is_empty
    assert "org='ACME'" in sm.seeds.summary
    assert "1 domain(s)" in sm.seeds.summary
