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
    check, apply = seen
    assert check[0][:3] == ["/usr/sbin/nft", "-c", "-f"] and apply[0][:2] == ["/usr/sbin/nft", "-f"]  # dry run first
    rules = apply[1]
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
