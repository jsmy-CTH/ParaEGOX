"""PXWP v1 Python reference worker.

`Ready` is only a protocol compatibility handshake; it is not Runtime
readiness. RuntimeHost remains the sole lifecycle and admission owner.
"""

from .runner import FaultMode, ReferenceWorker

__all__ = ["FaultMode", "ReferenceWorker"]
