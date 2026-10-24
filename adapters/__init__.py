"""External model adapters (§41).

External detector code is reached **only** through this package's
:class:`~adapters.base.BaseAdapter` contract, never called directly from the
engine. Swapping NSFWJS for OpenNSFW2 is a registry change, which is what keeps
the firewall, API and policy untouched when models evolve (§50).

```python
from adapters import build_adapter, describe_all

adapter = build_adapter("fast_path", session_manager=manager)
result = adapter.predict(image_bytes)      # -> AdapterResult | None
print(describe_all(manager))                # license/availability introspection
```

All adapters ship without weights and report ``available == False`` until an
artifact is mounted; see ``docs/MODEL_PROVENANCE.md``.
"""

from adapters.base import AdapterCategory, AdapterResult, BaseAdapter
from adapters.labels import (
    LabelSidecar,
    LabelSidecarError,
    load_labels,
    write_labels,
)
from adapters.registry import (
    ADAPTER_REGISTRY,
    available_adapters,
    build_adapter,
    describe_all,
    ensemble_score,
)
from adapters.vision import (
    CLIPZeroShotAdapter,
    HuggingFaceViTAdapter,
    NSFWJSAdapter,
    NuditaAdapter,
    OpenNSFW2Adapter,
)

__all__ = [
    "ADAPTER_REGISTRY",
    "AdapterCategory",
    "AdapterResult",
    "BaseAdapter",
    "CLIPZeroShotAdapter",
    "HuggingFaceViTAdapter",
    "LabelSidecar",
    "LabelSidecarError",
    "NSFWJSAdapter",
    "NuditaAdapter",
    "OpenNSFW2Adapter",
    "available_adapters",
    "build_adapter",
    "describe_all",
    "ensemble_score",
    "load_labels",
    "write_labels",
]