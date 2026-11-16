"""The privileged helper rejects hostile input before running anything and never touches foreign resources."""
import importlib.util
import json
import pathlib
import re

import pytest

HELPER = pathlib.Path(__file__).parents[2] / "helper" / "vpnix_create_helper.py"
spec = importlib.util.spec_from_file_location("helper", HELPER)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
KEY = "A" * 43 + "="
WG = {"iface": "wg0", "listen_port": 51820, "private_key": KEY, "addresses": ["10.0.0.1/24"], "mtu": 1420, "peers": []}


def call(method, **params):
    return helper.dispatch(json.dumps({"method": method, "params": params}).encode())


@pytest.fixture
def no_exec(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("a process was started for invalid input")
    monkeypatch.setattr(helper.subprocess, "run", boom)


@pytest.mark.parametrize("method,params", [
    ("wg.sync", {**WG, "iface": "eth0"}),
    ("wg.sync", {**WG, "iface": "wg0; reboot"}),
    ("wg.sync", {**WG, "listen_port": 70000}),
    ("wg.sync", {**WG, "private_key": "$(id)"}),
    ("wg.sync", {**WG, "peers": [{"public_key": KEY, "allowed_ips": ["0.0.0.0/0"]}]}),  # server side must be /32
    ("wg.service", {"iface": "wg0", "action": "mask"}),
    ("net.port_in_use", {"port": 53, "transport": "icmp"}),
    ("fw.apply", {"instances": [{"iface": "eth0", "port": 51820}]}),
    ("fw.apply", {"instances": [{"iface": "wg0", "port": 51820}], "egress": "eth0\"; flush ruleset"}),
])
def test_hostile_input_rejected_without_running_anything(no_exec, method, params):
    assert "invalid request" in call(method, **params)["error"]


def test_unknown_method():
    assert call("os.system", cmd="id")["error"] == "unknown method"


def test_refuses_unmanaged_wireguard_interface(tmp_path, monkeypatch):
    monkeypatch.setattr(helper, "WG_DIR", str(tmp_path))
    (tmp_path / "wg0.conf").write_text("[Interface]\nPrivateKey = x\n")  # someone's own WireGuard
    for method, params in (("wg.delete", {"iface": "wg0"}), ("wg.service", {"iface": "wg0", "action": "stop"}),
                           ("wg.sync", {"iface": "wg0", "listen_port": 51820, "private_key": KEY,
                                        "addresses": ["10.0.0.1/24"], "mtu": 1420, "peers": []})):
        assert "not managed by VPNix Create" in call(method, **params)["error"]
    assert (tmp_path / "wg0.conf").read_text().startswith("[Interface]")  # untouched


def test_firewall_only_replaces_own_table(monkeypatch):
    seen = []

    class R:
        returncode, stdout, stderr = 0, "", ""

    monkeypatch.setattr(helper.subprocess, "run", lambda argv, input=None, **k: seen.append((argv, input)) or R())
    out = call("fw.apply", instances=[{"iface": "wg0", "port": 51820, "subnets": ["10.8.0.0/24", "fd00:8::/64"],
                                       "nat": True, "isolate_clients": True}], egress="eth0")
    assert out["result"]["ok"]
    nft = [(argv, inp) for argv, inp in seen if argv[0] == "/usr/sbin/nft"]
    assert nft[0][0][:3] == ["/usr/sbin/nft", "-c", "-f"]  # dry run first
    rules = next(inp for argv, inp in nft if argv[:2] == ["/usr/sbin/nft", "-f"])
    tables = set(re.findall(r"table inet (\S+)", rules))
    assert tables == {"vpnix_create"}  # nothing outside the application's own table
    assert "udp dport 51820 accept" in rules and 'ip saddr 10.8.0.0/24 oifname "eth0" masquerade' in rules
    assert 'ip6 saddr fd00:8::/64 oifname "eth0" masquerade' in rules
    assert 'iifname "wg0" oifname "wg0" accept' not in rules  # clients isolated from each other


def test_sync_writes_marked_config(tmp_path, monkeypatch):
    monkeypatch.setattr(helper, "WG_DIR", str(tmp_path))

    class R:
        returncode, stdout, stderr = 1, "", ""  # interface not up yet: config only
    monkeypatch.setattr(helper.subprocess, "run", lambda *a, **k: R())
    r = call("wg.sync", iface="wg3", listen_port=51823, private_key=KEY, addresses=["10.9.0.1/24"], mtu=1420,
             peers=[{"public_key": KEY, "preshared_key": KEY, "allowed_ips": ["10.9.0.2/32"]}])
    assert r["result"]["peers"] == 1
    conf = (tmp_path / "wg3.conf").read_text()
    assert conf.startswith(helper.MARKER) and "AllowedIPs = 10.9.0.2/32" in conf and "ListenPort = 51823" in conf


def test_ui_test_helper_refuses_production_database(monkeypatch):
    from vpnix_create import testing
    from vpnix_create.config import get_settings
    monkeypatch.setenv("VPNIX_UI_TEST_HELPER", "1")
    monkeypatch.setattr(get_settings(), "database_url", "postgresql+psycopg://x@db/vpnix")
    with pytest.raises(RuntimeError):
        testing.enabled()


CERT = "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n"
OVPN = {"iface": "ovpn0", "port": 1194, "proto": "udp", "network": "10.30.0.0/24", "network6": None, "mtu": 1500,
        "dns": ["1.1.1.1"], "ca": CERT, "cert": CERT, "key": "-----BEGIN PRIVATE KEY-----\nQUJD\n-----END PRIVATE KEY-----\n",
        "tls_crypt": "-----BEGIN OpenVPN Static key V1-----\nab\n-----END OpenVPN Static key V1-----\n",
        "crl": "-----BEGIN X509 CRL-----\nQUJD\n-----END X509 CRL-----\n", "clients": []}


@pytest.fixture
def no_fs(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("filesystem changed for invalid input")
    monkeypatch.setattr(helper.ovpn_ops.os, "makedirs", boom)
    monkeypatch.setattr(helper.ovpn_ops, "_write", boom)


@pytest.mark.parametrize("patch", [
    {"iface": "eth0"}, {"iface": "wg0"}, {"proto": "icmp"}, {"network": "8.8.8.0/24"},
    {"network6": "2a00:1450::/64"},
    {"key": OVPN["key"] + "up /bin/sh\n"},                        # directive smuggled after a PEM
    {"crl": "x"},
    {"clients": [{"cn": "c" + "0" * 24 + "\nscript-security 3", "ip": "10.30.0.2"}]},  # newline injection
    {"clients": [{"cn": "../../etc/passwd", "ip": "10.30.0.2"}]},  # path traversal
    {"clients": [{"cn": "c" + "a" * 24, "ip": "10.99.0.2"}]},     # address outside the pool
])
def test_ovpn_apply_rejects_injection_before_writing(no_exec, no_fs, patch):
    assert "invalid request" in call("ovpn.apply", **{**OVPN, **patch})["error"]


def test_ovpn_refuses_foreign_instance(tmp_path, monkeypatch):
    monkeypatch.setattr(helper.ovpn_ops, "SERVER_DIR", str(tmp_path))
    (tmp_path / "ovpn0.conf").write_text("port 1194\n")  # someone's own OpenVPN server
    assert "not managed" in call("ovpn.apply", **OVPN)["error"]
    assert "not managed" in call("ovpn.delete", iface="ovpn0")["error"]
    assert (tmp_path / "ovpn0.conf").read_text() == "port 1194\n"



class _R:
    returncode, stdout, stderr = 0, "", ""


@pytest.fixture
def nft_log(monkeypatch):
    seen = []

    def fake(argv, input=None, **k):
        seen.append((argv, input))
        r = _R()
        if argv[1:3] == ["list", "table"]:
            r.stdout = "table inet vpnix_create { # previous\n}\n"
        return r
    monkeypatch.setattr(helper.subprocess, "run", fake)
    return seen


def _applied(seen):
    return [inp for argv, inp in seen if argv[:2] == ["/usr/sbin/nft", "-f"]]


def test_custom_rules_and_management_rendered(nft_log):
    out = call("fw.apply", instances=[], custom_rules=[
        {"action": "accept", "proto": "tcp", "ports": "8000-8100", "source": "198.51.100.0/24", "comment": "office"},
        {"action": "drop", "proto": "udp", "ports": 53, "source": "2001:db8::/32"},
        {"action": "drop", "proto": "any", "source": "203.0.113.9"}],
        management={"ports": [443, 80], "networks": ["192.0.2.0/24", "2001:db8:1::/48"]})
    assert out["result"]["ok"]
    rules = _applied(nft_log)[0]
    assert 'ip saddr 198.51.100.0/24 tcp dport 8000-8100 accept comment "office"' in rules
    assert "ip6 saddr 2001:db8::/32 udp dport 53 drop" in rules and "ip saddr 203.0.113.9/32 drop" in rules
    assert "meta nfproto ipv4 tcp dport { 80, 443 } ip saddr != { 192.0.2.0/24 } drop" in rules
    assert "meta nfproto ipv6 tcp dport { 80, 443 } ip6 saddr != { 2001:db8:1::/48 } drop" in rules
    assert rules.index("ip saddr != { 192.0.2.0/24 }") < rules.index('comment "office"')  # guard first


@pytest.mark.parametrize("rule", [
    {"action": "reject", "proto": "tcp"}, {"action": "drop", "proto": "icmp"},
    {"action": "drop", "proto": "any", "ports": 22},
    {"action": "drop", "proto": "tcp", "ports": "22; flush ruleset"},
    {"action": "drop", "proto": "tcp", "comment": 'x" accept'},
    {"action": "drop", "proto": "tcp", "source": "not-a-net"},
])
def test_custom_rule_injection_rejected(no_exec, rule):
    assert "invalid request" in call("fw.apply", instances=[], custom_rules=[rule])["error"]


def test_timed_rollback_restores_previous_table_unless_confirmed(nft_log):
    r = call("fw.apply", instances=[], custom_rules=[{"action": "drop", "proto": "tcp", "ports": 443}], rollback_seconds=60)
    token = r["result"]["confirm_token"]
    assert call("fw.pending")["result"]["pending"] is True
    assert "invalid request" in call("fw.confirm", token="wrong")["error"]
    assert call("fw.confirm", token=token)["result"]["ok"]
    assert call("fw.pending")["result"]["pending"] is False
    r = call("fw.apply", instances=[], custom_rules=[{"action": "drop", "proto": "tcp", "ports": 443}], rollback_seconds=60)
    helper._pending["timer"].cancel()
    helper._pending["timer"].function()  # the deadline passes without confirmation
    assert "# previous" in _applied(nft_log)[-1]  # the saved table was put back
    assert call("fw.pending")["result"]["pending"] is False


def test_fw_ports_accepts_single_port_string():
    assert helper._v_ports("8443") == "8443"
    assert helper._v_ports(8443) == "8443"
    assert helper._v_ports("8000-8100") == "8000-8100"
    for bad in ("0", "70000", "8100-8000", "80;drop", "80 443"):
        with pytest.raises(helper.Invalid):
            helper._v_ports(bad)
