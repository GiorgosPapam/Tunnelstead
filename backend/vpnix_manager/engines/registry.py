from .openvpn import OpenVPNEngine
from .wireguard import WireGuardEngine

# A protocol is listed only once its whole lifecycle is implemented and tested (unit + real-host e2e).
ENGINES = {"wireguard": WireGuardEngine(), "openvpn": OpenVPNEngine()}


def engine(protocol: str):
    try:
        return ENGINES[protocol]
    except KeyError:
        raise ValueError(f"Protocol '{protocol}' is not available") from None
