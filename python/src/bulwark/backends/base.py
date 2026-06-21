"""Backend helpers. A "backend" is just a callable ``(messages) -> str``.

Bulwark is model-agnostic: the simplest backend is a plain function. The
adapters in this package are thin conveniences around popular SDKs and are
imported lazily so the SDKs stay optional.
"""

from __future__ import annotations

from typing import Callable, Dict, List

Messages = List[Dict[str, str]]


class FunctionBackend:
    """Wrap any ``(messages) -> str`` callable as a backend object."""

    def __init__(self, fn: Callable[[Messages], str]):
        self._fn = fn

    def __call__(self, messages: Messages) -> str:
        return self._fn(messages)
