"""OpenVPN engine: openvpn-server@ovpnN per instance, own CA per instance, certificate per client.

Storage (no secrets in clear): instance.private_key_enc = encrypted JSON {ca_cert, ca_key, server_cert, server_key,
tls_crypt}; instance.public_key = CA fingerprint; client.public_key = certificate fingerprint;
client.psk_enc = encrypted client certificate; client.private_key_enc = encrypted client key.
"""
import ipaddress
import json

from .. import pki
from .base import VpnEngine
from .wireguard import client_routes


class OpenVPNEngine(VpnEngine):
    protocol, transports, default_port, iface_prefix = "openvpn", {"udp", "tcp"}, 1194, "ovpn"
    supports_qr, supports_own_key, session_counters, file_ext = False, False, True, "ovpn"
    port_range = (1194, 1294)

    def check_installation(self, helper):
        return {"ok": True, **helper.call("sys.status")}

    def create_keys(self, label: str = "instance"):
        ca_cert, ca_key = pki.new_ca(label)
        server_cert, server_key = pki.issue(ca_cert, ca_key, "server", server=True)
        bundle = {"ca_cert": ca_cert, "ca_key": ca_key, "server_cert": server_cert, "server_key": server_key,
                  "tls_crypt": pki.tls_crypt_key()}
        return json.dumps(bundle), pki.info(ca_cert)["fingerprint"]

    def new_client_credentials(self, server_secret: str | None = None):
        b = json.loads(server_secret)
        cert, key = pki.issue(b["ca_cert"], b["ca_key"], pki.new_cn(), server=False)
        return {"private_key": key, "public_key": pki.info(cert)["fingerprint"], "psk": cert}

    def stats_key(self, client_cert: str) -> str:
        return pki.info(client_cert)["cn"]

    def apply(self, helper, instance, clients, server_secret, inactive_certs=()):
        b = json.loads(server_secret)
        serials = [pki.info(c)["serial"] for c in inactive_certs]
        helper.call("ovpn.apply", iface=instance.iface, port=instance.listen_port, proto=instance.transport,
                    network=instance.ipv4_cidr, network6=instance.ipv6_cidr, mtu=instance.mtu, dns=instance.dns,
                    ca=b["ca_cert"], cert=b["server_cert"], key=b["server_key"], tls_crypt=b["tls_crypt"],
                    crl=pki.crl(b["ca_cert"], b["ca_key"], serials),
                    clients=[{"cn": pki.info(c["psk"])["cn"], "ip": c["ipv4"], "ip6": c.get("ipv6")} for c in clients])

    def start(self, helper, instance):
        helper.call("ovpn.service", iface=instance.iface, action="enable")
        helper.call("ovpn.service", iface=instance.iface, action="restart")

    def stop(self, helper, instance):
        helper.call("ovpn.service", iface=instance.iface, action="stop")
        helper.call("ovpn.service", iface=instance.iface, action="disable")

    def delete(self, helper, instance):
        helper.call("ovpn.delete", iface=instance.iface)

    def status(self, helper, instance):
        return helper.call("ovpn.service", iface=instance.iface, action="status")

    def collect_stats(self, helper, instance):
        """Connected sessions; key = certificate CN, counters are per session."""
        return [{"key": c["cn"], "endpoint": c["endpoint"], "connected": True, "rx_bytes": c["rx_bytes"],
                 "tx_bytes": c["tx_bytes"]} for c in helper.call("ovpn.status", iface=instance.iface)["clients"]]

    def render_client_config(self, instance, client, private_key, psk, server_secret=None):
        b = json.loads(server_secret)
        host = instance.endpoint_host.strip("[]")
        lines = ["client", "dev tun", f"proto {instance.transport}", f"remote {host} {instance.listen_port}",
                 "nobind", "persist-key", "persist-tun", "remote-cert-tls server", "verify-x509-name server name",
                 "tls-version-min 1.2", "data-ciphers AES-256-GCM:CHACHA20-POLY1305", "auth SHA256",
                 f"tun-mtu {instance.mtu}", "verb 3"]
        routes = client_routes(instance, client)
        if "0.0.0.0/0" in routes:
            # Full tunnel: "ipv6" also captures IPv6 so it cannot leak around the VPN; block-outside-dns stops
            # Windows DNS leaks.
            lines += ["redirect-gateway def1 ipv6" if instance.ipv6_cidr else "redirect-gateway def1", "block-outside-dns"]
        else:
            for r in routes:
                n = ipaddress.ip_network(r, strict=False)
                lines.append(f"route {n.network_address} {n.netmask}" if n.version == 4 else f"route-ipv6 {n}")
        for d in (client.dns if client.dns is not None else instance.dns):
            lines.append(f"dhcp-option DNS {d}")
        lines += ["<ca>", b["ca_cert"].strip(), "</ca>", "<cert>", psk.strip(), "</cert>", "<key>", private_key.strip(), "</key>",
                  "<tls-crypt>", b["tls_crypt"].strip(), "</tls-crypt>"]
        return "\n".join(lines) + "\n"

    def cert_expiry(self, server_secret: str) -> dict:
        b = json.loads(server_secret)
        return {"ca": pki.info(b["ca_cert"])["not_after"], "server": pki.info(b["server_cert"])["not_after"]}
