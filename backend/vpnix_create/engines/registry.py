from .wireguard import WireGuardEngine

# OpenVPN joins in phase 3, only after its full lifecycle is implemented and tested.
ENGINES = {"wireguard": WireGuardEngine()}


def engine(protocol: str):
    try:
        return ENGINES[protocol]
    except KeyError:
        raise ValueError(f"Protocol '{protocol}' is not available") from None
