from .loki import LogQLBackend

__all__ = ("LogQLBackend",)

backends = {
    "loki": LogQLBackend,
}
