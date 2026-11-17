"""Role -> permission mapping. Every privileged route declares the permission it needs."""
from .models import Role

PERMISSIONS: dict[Role, set[str]] = {
    Role.VIEWER: {"view"},
    Role.OPERATOR: {"view", "clients.manage", "clients.secrets"},
    Role.ADMIN: {"view", "clients.manage", "clients.secrets", "instances.manage", "firewall.manage",
                 "users.manage", "system.manage", "audit.view"},
}


def has(role: Role, perm: str) -> bool:
    return perm in PERMISSIONS.get(role, set())
