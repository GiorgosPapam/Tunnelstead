"""OpenVPN operations for tunnelstead-helper (root). Standard library only.

OpenVPN configuration is line-based, so a newline or quote inside any value could inject directives
(e.g. `script-security 2` + `up /bin/sh`). Every value is therefore validated against a strict pattern before
anything is written, and every write happens only after all validation succeeded.
Only instances whose config carries the Tunnelstead marker are ever modified (ovpn0 ... ovpn999).
"""
import ipaddress
import os
import re
import shutil
import socket
import subprocess

SERVER_DIR = "/etc/openvpn/server"
RUN_DIR = "/run/tunnelstead"
MARKER = "# Managed by Tunnelstead - do not edit by hand"
IFACE = re.compile(r"^ovpn[0-9]{1,3}$")
CN = re.compile(r"^c[0-9a-f]{24}$")
PEM = {
    "cert": re.compile(r"^-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+-----END CERTIFICATE-----\n?$"),
    "key": re.compile(r"^-----BEGIN PRIVATE KEY-----\n[A-Za-z0-9+/=\n]+-----END PRIVATE KEY-----\n?$"),
    "crl": re.compile(r"^-----BEGIN X509 CRL-----\n[A-Za-z0-9+/=\n]+-----END X509 CRL-----\n?$"),
    "tls": re.compile(r"^-----BEGIN OpenVPN Static key V1-----\n[0-9a-f\n]+-----END OpenVPN Static key V1-----\n?$"),
}


class Invalid(ValueError):
    pass


def v_iface(x):
    if not isinstance(x, str) or not IFACE.match(x):
        raise Invalid("OpenVPN interface must look like ovpn0 … ovpn999")
    return x


def v_pem(kind, v):
    if not isinstance(v, str) or len(v) > 20000 or not PEM[kind].match(v):
        raise Invalid(f"bad {kind} PEM")
    return v if v.endswith("\n") else v + "\n"


def _conf(iface):
    return os.path.join(SERVER_DIR, f"{iface}.conf")


def managed(iface) -> bool:
    try:
        with open(_conf(iface)) as f:
            return f.readline().rstrip("\n") == MARKER
    except FileNotFoundError:
        return False


def _write(path, content, mode):
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as f:
        f.write(content)
    os.replace(tmp, path)


def _systemctl(*args, check=True):
    r = subprocess.run(["/usr/bin/systemctl", *args], capture_output=True, text=True, timeout=30)
    if check and r.returncode:
        raise RuntimeError(f"systemctl {' '.join(args)} failed: {r.stderr.strip()[:300]}")
    return r


def _mgmt(iface, command):
    path = f"{RUN_DIR}/{iface}.mgmt"
    if not os.path.exists(path):
        return ""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect(path)
            s.recv(4096)  # banner
            s.sendall(command.encode() + b"\n")
            return s.recv(4096).decode(errors="replace")
    except OSError:
        return ""


def apply(iface, port, proto, network, network6, mtu, dns, ca, cert, key, tls_crypt, crl, clients):
    """Full desired state: server files, one ccd entry per active client (ccd-exclusive), CRL.
    Clients removed from the list lose their ccd entry and their live session is killed."""
    iface = v_iface(iface)
    if not (isinstance(port, int) and 1024 <= port <= 65535) or proto not in ("udp", "tcp"):
        raise Invalid("bad port/transport")
    net = ipaddress.ip_network(network, strict=True)
    if net.version != 4 or not net.is_private or not 16 <= net.prefixlen <= 29:
        raise Invalid("IPv4 pool must be a private /16-/29")
    net6 = None
    if network6:
        net6 = ipaddress.ip_network(network6, strict=True)
        if net6.version != 6 or not net6.subnet_of(ipaddress.ip_network("fc00::/7")) or not 64 <= net6.prefixlen <= 112:
            raise Invalid("IPv6 pool must be a ULA /64-/112")
    if not (isinstance(mtu, int) and 1280 <= mtu <= 1500):
        raise Invalid("bad MTU")
    dns = [str(ipaddress.ip_address(d)) for d in (dns or [])][:4]
    files = {"ca.crt": v_pem("cert", ca), "server.crt": v_pem("cert", cert), "server.key": v_pem("key", key),
             "tls-crypt.key": v_pem("tls", tls_crypt), "crl.pem": v_pem("crl", crl)}
    if not isinstance(clients, list) or len(clients) > 5000:
        raise Invalid("bad client list")
    ccd = {}
    for c in clients:
        cn, ip = c["cn"], ipaddress.ip_address(c["ip"])
        if not isinstance(cn, str) or not CN.match(cn) or ip not in net:
            raise Invalid("bad client entry")
        lines = [f"ifconfig-push {ip} {net.netmask}"]
        if c.get("ip6"):
            ip6 = ipaddress.ip_address(c["ip6"])
            if not net6 or ip6 not in net6:
                raise Invalid("client IPv6 outside the pool")
            lines.append(f"ifconfig-ipv6-push {ip6}/{net6.prefixlen} {next(net6.hosts())}")
        ccd[cn] = "\n".join(lines) + "\n"
    if os.path.exists(_conf(iface)) and not managed(iface):
        raise Invalid(f"{iface} exists and is not managed by Tunnelstead; refusing to touch it")
    # ---- everything validated: now write
    base = os.path.join(SERVER_DIR, iface)
    os.makedirs(os.path.join(base, "ccd"), mode=0o755, exist_ok=True)
    for name, content in files.items():
        _write(os.path.join(base, name), content, 0o644 if name in ("ca.crt", "crl.pem") else 0o600)
    existing = set(os.listdir(os.path.join(base, "ccd")))
    for cn, content in ccd.items():
        _write(os.path.join(base, "ccd", cn), content, 0o644)
    for gone in existing - set(ccd):
        if CN.match(gone):
            os.unlink(os.path.join(base, "ccd", gone))
            _mgmt(iface, f"kill {gone}")  # end the live session now
    proto_line = "proto udp4" if proto == "udp" else "proto tcp4-server"
    lines = [MARKER, f"dev {iface}", "dev-type tun", "topology subnet", proto_line,
             f"port {port}", f"server {net.network_address} {net.netmask}",
             f"ca {base}/ca.crt", f"cert {base}/server.crt", f"key {base}/server.key", "dh none",
             f"tls-crypt {base}/tls-crypt.key", f"crl-verify {base}/crl.pem",
             f"client-config-dir {base}/ccd", "ccd-exclusive",
             "tls-version-min 1.2", "data-ciphers AES-256-GCM:CHACHA20-POLY1305", "data-ciphers-fallback AES-256-GCM",
             "auth SHA256", "remote-cert-tls client", "keepalive 10 60", f"tun-mtu {mtu}",
             "persist-key", "persist-tun", "user nobody", "group nogroup",
             f"status {RUN_DIR}/{iface}.status 10", "status-version 3", f"management {RUN_DIR}/{iface}.mgmt unix", "verb 3"]
    lines += [f'push "dhcp-option DNS {d}"' for d in dns]
    if net6:
        lines.append(f"server-ipv6 {net6}")
    if proto == "udp":
        lines += ["explicit-exit-notify 1", "multihome"]  # reply from the address the client contacted
    _write(_conf(iface), "\n".join(lines) + "\n", 0o644)
    return {"ok": True, "clients": len(ccd)}


def service(iface, action):
    iface = v_iface(iface)
    if action not in ("start", "stop", "restart", "enable", "disable", "status"):
        raise Invalid("bad action")
    if not managed(iface):
        raise Invalid(f"{iface} is not managed by Tunnelstead")
    unit = f"openvpn-server@{iface}.service"
    if action == "status":
        return {"active": _systemctl("is-active", unit, check=False).stdout.strip() == "active",
                "enabled": _systemctl("is-enabled", unit, check=False).stdout.strip() == "enabled"}
    _systemctl(action, unit)
    return {"ok": True}


def status(iface):
    """Connected sessions from the status file (refreshed every 10 s). Never returns key material."""
    iface = v_iface(iface)
    path, clients = f"{RUN_DIR}/{iface}.status", []
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                p = line.rstrip("\n").split("\t")
                if p[0] == "CLIENT_LIST" and len(p) > 8 and p[1] != "UNDEF":
                    clients.append({"cn": p[1], "endpoint": p[2], "rx_bytes": int(p[5]), "tx_bytes": int(p[6]),
                                    "connected_since": int(p[8])})
    return {"clients": clients}


def delete(iface):
    iface = v_iface(iface)
    if not managed(iface):
        if not os.path.exists(_conf(iface)):
            return {"ok": True, "note": "already gone"}
        raise Invalid(f"{iface} is not managed by Tunnelstead")
    _systemctl("disable", "--now", f"openvpn-server@{iface}.service", check=False)
    os.unlink(_conf(iface))
    shutil.rmtree(os.path.join(SERVER_DIR, iface), ignore_errors=True)
    return {"ok": True}
