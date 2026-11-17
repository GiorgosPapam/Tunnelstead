"""Interface every VPN engine implements. An engine is registered (and shown in the UI) only after its
whole lifecycle is implemented and tested. Engines manage only their own resources (interface namespace)."""
from abc import ABC, abstractmethod


class VpnEngine(ABC):
    protocol: str
    transports: set[str]
    default_port: int
    iface_prefix: str

    @abstractmethod
    def check_installation(self, helper) -> dict: ...

    @abstractmethod
    def create_keys(self) -> tuple[str, str]: ...

    @abstractmethod
    def new_client_credentials(self) -> dict: ...

    @abstractmethod
    def apply(self, helper, instance, clients: list, server_private_key: str) -> None: ...

    @abstractmethod
    def start(self, helper, instance) -> None: ...

    @abstractmethod
    def stop(self, helper, instance) -> None: ...

    @abstractmethod
    def delete(self, helper, instance) -> None: ...

    @abstractmethod
    def status(self, helper, instance) -> dict: ...

    @abstractmethod
    def collect_stats(self, helper, instance) -> list[dict]: ...

    @abstractmethod
    def render_client_config(self, instance, client, private_key: str, psk: str) -> str: ...
