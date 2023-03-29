from .loki import LogQLBackend


backends = {
    "loki": LogQLBackend,
}
