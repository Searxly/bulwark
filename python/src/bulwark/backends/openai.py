"""OpenAI chat-completions backend (optional — needs ``pip install openai``)."""

from __future__ import annotations

from typing import Dict, List, Optional


class OpenAIBackend:
    """Adapter for the OpenAI Python SDK.

        from openai import OpenAI
        from bulwark import Bulwark
        from bulwark.backends.openai import OpenAIBackend

        guard = Bulwark(llm=OpenAIBackend(model="gpt-4o-mini"))
    """

    def __init__(self, model: str = "gpt-4o-mini", client: Optional[object] = None, **create_kwargs: object):
        if client is None:
            try:
                from openai import OpenAI  # type: ignore
            except ImportError as exc:  # pragma: no cover - import guard
                raise ImportError("OpenAIBackend requires `pip install openai`.") from exc
            client = OpenAI()
        self.client = client
        self.model = model
        self.create_kwargs = create_kwargs

    def __call__(self, messages: List[Dict[str, str]]) -> str:
        resp = self.client.chat.completions.create(  # type: ignore[attr-defined]
            model=self.model,
            messages=messages,
            **self.create_kwargs,
        )
        return resp.choices[0].message.content or ""
