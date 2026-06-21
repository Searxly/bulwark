"""Anthropic Messages backend (optional — needs ``pip install anthropic``).

Anthropic keeps the system prompt out of the ``messages`` array, so this
adapter lifts Bulwark's ``system`` message into the ``system`` parameter where
it carries the most weight.
"""

from __future__ import annotations

from typing import Dict, List, Optional


class AnthropicBackend:
    """Adapter for the Anthropic Python SDK.

        from bulwark import Bulwark
        from bulwark.backends.anthropic import AnthropicBackend

        guard = Bulwark(llm=AnthropicBackend(model="claude-opus-4-8"))
    """

    def __init__(
        self,
        model: str = "claude-opus-4-8",
        client: Optional[object] = None,
        max_tokens: int = 1024,
        **create_kwargs: object,
    ):
        if client is None:
            try:
                import anthropic  # type: ignore
            except ImportError as exc:  # pragma: no cover - import guard
                raise ImportError("AnthropicBackend requires `pip install anthropic`.") from exc
            client = anthropic.Anthropic()
        self.client = client
        self.model = model
        self.max_tokens = max_tokens
        self.create_kwargs = create_kwargs

    def __call__(self, messages: List[Dict[str, str]]) -> str:
        system = "\n\n".join(m["content"] for m in messages if m["role"] == "system")
        convo = [m for m in messages if m["role"] != "system"]
        resp = self.client.messages.create(  # type: ignore[attr-defined]
            model=self.model,
            system=system,
            messages=convo,
            max_tokens=self.max_tokens,
            **self.create_kwargs,
        )
        return "".join(block.text for block in resp.content if getattr(block, "type", None) == "text")
