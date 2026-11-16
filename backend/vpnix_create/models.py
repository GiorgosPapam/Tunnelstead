"""Phase 1 schema: users, sessions, settings, audit log. VPN tables arrive in Phase 2."""
from __future__ import annotations

import enum
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    false,
)
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


class Role(enum.StrEnum):
    ADMIN = "admin"        # everything
    OPERATOR = "operator"  # manage clients; read the rest
    VIEWER = "viewer"      # read-only administrator; never sees secrets


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    email: Mapped[str | None] = mapped_column(String(254), nullable=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[Role] = mapped_column(Enum(Role), default=Role.VIEWER)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    mfa_secret_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    recovery_hashes: Mapped[list] = mapped_column(JSON, default=list)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)


class UserSession(Base):
    __tablename__ = "user_sessions"
    id: Mapped[int] = mapped_column(primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    csrf_hash: Mapped[str] = mapped_column(String(64))
    mfa_pending: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(200), nullable=True)


class Setting(Base):
    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON)


class AuditEntry(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    actor_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    actor: Mapped[str | None] = mapped_column(String(64), nullable=True)
    category: Mapped[str] = mapped_column(String(16), index=True)  # auth | admin | vpn | system
    action: Mapped[str] = mapped_column(String(64), index=True)
    target: Mapped[str | None] = mapped_column(String(128), nullable=True)
    ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, default=True)
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))


class InstanceState(enum.StrEnum):
    RUNNING = "running"
    STOPPED = "stopped"


class ClientStatus(enum.StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"
    REVOKED = "revoked"
    EXPIRED = "expired"
    OVER_QUOTA = "over_quota"


class VpnInstance(Base):
    """One VPN server instance: one interface + one listening port, serving many clients."""
    __tablename__ = "vpn_instances"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    protocol: Mapped[str] = mapped_column(String(16), default="wireguard")
    iface: Mapped[str] = mapped_column(String(15), unique=True)
    listen_port: Mapped[int] = mapped_column(Integer)
    transport: Mapped[str] = mapped_column(String(3), default="udp")
    endpoint_host: Mapped[str] = mapped_column(String(253))
    egress_iface: Mapped[str | None] = mapped_column(String(15), nullable=True)
    ipv4_cidr: Mapped[str] = mapped_column(String(18))
    ipv6_cidr: Mapped[str | None] = mapped_column(String(43), nullable=True)
    dns: Mapped[list] = mapped_column(JSON, default=list)
    mtu: Mapped[int] = mapped_column(Integer, default=1420)
    keepalive: Mapped[int] = mapped_column(Integer, default=25)
    routing_mode: Mapped[str] = mapped_column(String(8), default="full")  # full | split
    split_routes: Mapped[list] = mapped_column(JSON, default=list)
    nat: Mapped[bool] = mapped_column(Boolean, default=True)
    isolate_clients: Mapped[bool] = mapped_column(Boolean, default=True)
    private_key_enc: Mapped[str] = mapped_column(Text)
    public_key: Mapped[str] = mapped_column(String(44))
    state: Mapped[InstanceState] = mapped_column(Enum(InstanceState), default=InstanceState.RUNNING)
    ca_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    server_cert_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Client(Base):
    __tablename__ = "clients"
    __table_args__ = (UniqueConstraint("instance_id", "ipv4"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    instance_id: Mapped[int] = mapped_column(ForeignKey("vpn_instances.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(64))
    description: Mapped[str] = mapped_column(String(500), default="")
    tags: Mapped[list] = mapped_column(JSON, default=list)
    public_key: Mapped[str] = mapped_column(String(44), unique=True)
    private_key_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    psk_enc: Mapped[str] = mapped_column(Text)
    ipv4: Mapped[str] = mapped_column(String(15))
    ipv6: Mapped[str | None] = mapped_column(String(39), nullable=True)
    allowed_ips: Mapped[list | None] = mapped_column(JSON, nullable=True)  # client-side routes override
    dns: Mapped[list | None] = mapped_column(JSON, nullable=True)
    keepalive: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[ClientStatus] = mapped_column(Enum(ClientStatus), default=ClientStatus.ACTIVE)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    quota_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    rx_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    tx_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    # How live statistics identify this client (WireGuard public key / OpenVPN certificate CN).
    stats_key: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    # OpenVPN reports per-session counters; remember the last sample to accumulate lifetime totals.
    session_rx: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    session_tx: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    cert_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_handshake: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_endpoint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ClientStat(Base):
    __tablename__ = "client_stats"
    id: Mapped[int] = mapped_column(primary_key=True)
    client_id: Mapped[int] = mapped_column(ForeignKey("clients.id", ondelete="CASCADE"), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    rx_bytes: Mapped[int] = mapped_column(BigInteger)
    tx_bytes: Mapped[int] = mapped_column(BigInteger)


class RetiredCert(Base):
    """OpenVPN certificates replaced by "regenerate": kept (encrypted) only so they stay on the CRL."""
    __tablename__ = "retired_certs"
    id: Mapped[int] = mapped_column(primary_key=True)
    instance_id: Mapped[int] = mapped_column(ForeignKey("vpn_instances.id", ondelete="CASCADE"), index=True)
    cert_enc: Mapped[str] = mapped_column(Text)
    retired_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class FirewallRule(Base):
    """Administrator-defined input rule, applied inside the application's own nftables table only."""
    __tablename__ = "firewall_rules"
    id: Mapped[int] = mapped_column(primary_key=True)
    position: Mapped[int] = mapped_column(Integer, default=0)
    action: Mapped[str] = mapped_column(String(6))          # accept | drop
    proto: Mapped[str] = mapped_column(String(3))           # tcp | udp | any
    ports: Mapped[str | None] = mapped_column(String(11), nullable=True)   # "443" or "8000-8100"
    source: Mapped[str | None] = mapped_column(String(43), nullable=True)  # CIDR (IPv4 or IPv6)
    comment: Mapped[str] = mapped_column(String(64), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
