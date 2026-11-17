from cryptography import x509
from vpnix_manager import collector, pki

from tests.conftest import login, make_user

OV = {"name": "OVPN-Primary", "protocol": "openvpn", "transport": "udp", "iface": "ovpn0", "listen_port": 1194,
      "endpoint_host": "vpn.example.org", "ipv4_cidr": "10.30.0.0/24", "ipv6_cidr": "fd30:30::/64",
      "dns": ["9.9.9.9"], "mtu": 1500}


def _blk(conf, tag):
    return conf.split(f"<{tag}>\n")[1].split(f"\n</{tag}>")[0] + "\n"


def _admin(app, db):
    make_user(db, "boss")
    return login(app, "boss")


def _revoked(helper, iface, cert_pem):
    crl = x509.load_pem_x509_crl(helper.crl[iface].encode())
    return crl.get_revoked_certificate_by_serial_number(pki.info(cert_pem)["serial"]) is not None


def test_recommendation_uses_openvpn_defaults(app, db, helper):
    r = _admin(app, db).get("/api/instances/recommend", params={"protocol": "openvpn", "transport": "tcp"}).json()
    assert r["port"] == 1194 and r["iface"] == "ovpn0" and r["transport"] == "tcp"


def test_openvpn_lifecycle_with_crl(app, db, helper):
    c = _admin(app, db)
    inst = c.post("/api/instances", json=OV)
    assert inst.status_code == 201, inst.text
    inst = inst.json()
    assert inst["ca_expires_at"] and inst["server_cert_expires_at"] and helper.services["ovpn0"]
    assert c.post("/api/clients", json={"instance_id": inst["id"], "name": "x", "public_key": "A" * 43 + "="}).status_code == 422
    cl = c.post("/api/clients", json={"instance_id": inst["id"], "name": "Office PC"}).json()
    assert cl["protocol"] == "openvpn" and cl["cert_expires_at"] and cl["ipv6"] == "fd30:30::2"
    entry = next(iter(helper.ovpn["ovpn0"].values()))
    assert entry["ip"] == "10.30.0.2" and entry["ip6"] == "fd30:30::2"

    r = c.get(f"/api/clients/{cl['id']}/config")
    assert r.headers["content-disposition"].endswith('.ovpn"')
    conf = r.text
    assert "remote vpn.example.org 1194" in conf and "redirect-gateway def1 ipv6" in conf and "dhcp-option DNS 9.9.9.9" in conf
    ca, cert = x509.load_pem_x509_certificate(_blk(conf, "ca").encode()), _blk(conf, "cert")
    x509.load_pem_x509_certificate(cert.encode()).verify_directly_issued_by(ca)
    assert c.get(f"/api/clients/{cl['id']}/qr").status_code == 409

    c.post(f"/api/clients/{cl['id']}/disable")
    assert helper.ovpn["ovpn0"] == {} and _revoked(helper, "ovpn0", cert)
    c.post(f"/api/clients/{cl['id']}/enable")
    assert len(helper.ovpn["ovpn0"]) == 1 and not _revoked(helper, "ovpn0", cert)
    c.post(f"/api/clients/{cl['id']}/regenerate")
    new_cert = _blk(c.get(f"/api/clients/{cl['id']}/config").text, "cert")
    assert new_cert != cert and _revoked(helper, "ovpn0", cert) and not _revoked(helper, "ovpn0", new_cert)
    c.post(f"/api/clients/{cl['id']}/revoke")
    assert helper.ovpn["ovpn0"] == {} and _revoked(helper, "ovpn0", new_cert)


def test_tcp_split_tunnel_and_coexistence_with_wireguard(app, db, helper):
    from tests.conftest import WG1
    c = _admin(app, db)
    assert c.post("/api/instances", json=WG1).status_code == 201
    r = c.post("/api/instances", json={**OV, "transport": "tcp", "routing_mode": "split", "split_routes": ["192.168.7.0/24"],
                                       "ipv4_cidr": "10.31.0.0/24", "ipv6_cidr": None})
    assert r.status_code == 201, r.text
    cl = c.post("/api/clients", json={"instance_id": r.json()["id"], "name": "t"}).json()
    conf = c.get(f"/api/clients/{cl['id']}/config").text
    assert "proto tcp" in conf and "route 192.168.7.0 255.255.255.0" in conf and "redirect-gateway" not in conf
    assert {i["iface"] for i in [p for m, p in helper.calls if m == "fw.apply"][-1]["instances"]} == {"wg1", "ovpn0"}


def test_wireguard_cannot_use_tcp_and_foreign_openvpn_detected(app, db, helper):
    from tests.conftest import WG1
    c = _admin(app, db)
    r = c.post("/api/instances/validate", json={**WG1, "transport": "tcp"}).json()
    assert "UDP only" in r["errors"]["transport"]
    helper.foreign_wg.append("ovpn0")  # someone's own OpenVPN server config
    r = c.post("/api/instances/validate", json=OV).json()
    assert "not created by VPNix Manager" in r["errors"]["iface"]


def test_session_counters_become_totals(app, db, helper):
    c = _admin(app, db)
    iid = c.post("/api/instances", json=OV).json()["id"]
    cl = c.post("/api/clients", json={"instance_id": iid, "name": "s"}).json()
    cn = next(iter(helper.ovpn["ovpn0"]))
    for ep, rx in (("1.2.3.4:1", 100), ("1.2.3.4:1", 250), ("5.6.7.8:9", 40)):  # third sample = new session
        helper.sessions["ovpn0"] = [{"cn": cn, "endpoint": ep, "rx_bytes": rx, "tx_bytes": 0, "connected_since": 0}]
        collector.collect(db, helper)
    got = next(x for x in c.get("/api/clients").json() if x["id"] == cl["id"])
    assert got["rx_bytes"] == 290 and got["connected"]


def test_certificate_expiry_overview(app, db, helper):
    c = _admin(app, db)
    iid = c.post("/api/instances", json=OV).json()["id"]
    c.post("/api/clients", json={"instance_id": iid, "name": "e"})
    rows = c.get("/api/certificates").json()
    assert {r["kind"] for r in rows} == {"ca", "server", "client"}
    assert all(r["state"] == "ok" and r["days_left"] > 700 for r in rows)
