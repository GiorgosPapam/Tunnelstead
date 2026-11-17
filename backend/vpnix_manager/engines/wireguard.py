"""WireGuard engine. Keys are X25519 (the only curve WireGuard uses); every client also gets a preshared key."""
import base64
import ipaddress
import os
import re

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .base import VpnEngine

KEY_RE = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=$")


def keypair() -> tuple[str, str]:
    k = X25519PrivateKey.generate()
    priv = k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(priv).decode(), base64.b64encode(pub).decode()


def public_from_private(priv: str) -> str:
    k = X25519PrivateKey.from_private_bytes(base64.b64decode(priv))
    return base64.b64encode(k.public_key().public_bytes(serialization.Encoding.Raw,
                                                        serialization.PublicFormat.Raw)).decode()


def valid_key(k: str) -> bool:
    return bool(KEY_RE.match(k or ""))


def gateway(cidr: str) -> str:
    return str(next(ipaddress.ip_network(cidr).hosts()))


def client_routes(instance, client) -> list[str]:
    """What the client sends into the tunnel (its AllowedIPs)."""
    if client.allowed_ips:
        return client.allowed_ips
    if instance.routing_mode == "full":
        return ["0.0.0.0/0"] + (["::/0"] if instance.ipv6_cidr else [])
    return [instance.ipv4_cidr] + ([instance.ipv6_cidr] if instance.ipv6_cidr else []) + list(instance.split_routes)


class WireGuardEngine(VpnEngine):
    protocol, transports, default_port, iface_prefix = "wireguard", {"udp"}, 51820, "wg"
    supports_qr, supports_own_key, session_counters, file_ext = True, True, False, "conf"
    port_range = (51820, 51920)

    def check_installation(self, helper):
        s = helper.call("sys.status")
        return {"ok": s["wireguard_tools"] and s["nftables"], **s}

    def create_keys(self, label: str = "instance"):
        return keypair()

    def new_client_credentials(self, server_secret: str | None = None):
        priv, pub = keypair()
        return {"private_key": priv, "public_key": pub, "psk": base64.b64encode(os.urandom(32)).decode()}

    def apply(self, helper, instance, clients, server_private_key, inactive_certs=()):
        """Push the complete desired state; the helper applies it live without disturbing other clients."""
        addrs = [f"{gateway(instance.ipv4_cidr)}/{ipaddress.ip_network(instance.ipv4_cidr).prefixlen}"]
        if instance.ipv6_cidr:
            addrs.append(f"{gateway(instance.ipv6_cidr)}/{ipaddress.ip_network(instance.ipv6_cidr).prefixlen}")
        peers = [{"public_key": c["public_key"], "preshared_key": c["psk"],
                  "allowed_ips": [f"{c['ipv4']}/32"] + ([f"{c['ipv6']}/128"] if c.get("ipv6") else [])}
                 for c in clients]
        helper.call("wg.sync", iface=instance.iface, listen_port=instance.listen_port, private_key=server_private_key,
                    addresses=addrs, mtu=instance.mtu, peers=peers)

    def start(self, helper, instance):
        helper.call("wg.service", iface=instance.iface, action="enable")
        helper.call("wg.service", iface=instance.iface, action="restart")

    def stop(self, helper, instance):
        helper.call("wg.service", iface=instance.iface, action="stop")
        helper.call("wg.service", iface=instance.iface, action="disable")

    def delete(self, helper, instance):
        helper.call("wg.delete", iface=instance.iface)

    def status(self, helper, instance):
        return helper.call("wg.service", iface=instance.iface, action="status")

    def collect_stats(self, helper, instance):
        return [{"key": p["public_key"], "endpoint": p["endpoint"], "latest_handshake": p["latest_handshake"],
                 "rx_bytes": p["rx_bytes"], "tx_bytes": p["tx_bytes"]}
                for p in helper.call("wg.dump", iface=instance.iface).get("peers", [])]

    def stats_key(self, public_key: str) -> str:
        return public_key

    def render_client_config(self, instance, client, private_key, psk, server_secret=None):
        addrs = [f"{client.ipv4}/32"] + ([f"{client.ipv6}/128"] if client.ipv6 else [])
        host = instance.endpoint_host
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        dns = client.dns if client.dns is not None else instance.dns
        lines = ["[Interface]", f"PrivateKey = {private_key}", f"Address = {', '.join(addrs)}"]
        if dns:
            lines.append(f"DNS = {', '.join(dns)}")
        lines += [f"MTU = {instance.mtu}", "", "[Peer]", f"PublicKey = {instance.public_key}", f"PresharedKey = {psk}",
                  f"AllowedIPs = {', '.join(client_routes(instance, client))}", f"Endpoint = {host}:{instance.listen_port}"]
        ka = client.keepalive if client.keepalive is not None else instance.keepalive
        if ka:
            lines.append(f"PersistentKeepalive = {ka}")
        return "\n".join(lines) + "\n"
