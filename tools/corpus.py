"""Load and validate Bulwark's shared ground-truth corpus.

The corpus is the reason Bulwark can make claims with numbers attached. It lives
in ``corpus/parts/*.jsonl`` as language-agnostic JSONL so all three
implementations grade themselves against exactly the same cases.

Each line is one document:

    {"id": "io-001", "text": "...", "label": "attack",
     "expect_injected": true, "class": "instruction_override",
     "technique": "polite-indirect", "language": "en", "notes": "..."}

``expect_injected`` is ground truth — what a *correct* detector should say — not
a description of what Bulwark currently does. Entries Bulwark fails are the
point: they are the backlog.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterator, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS_DIR = REPO_ROOT / "corpus"
PARTS_DIR = CORPUS_DIR / "parts"

ATTACK_CLASSES = {
    "instruction_override",
    "role_injection",
    "prompt_leak",
    "exfiltration",
    "jailbreak",
    "tool_injection",
    "boundary_breakout",
    "encoding",
    "summary_poisoning",
    "agentic",
}


@dataclass(frozen=True)
class Case:
    """One corpus document plus its ground-truth label."""

    id: str
    text: str
    label: str                 # "attack" | "benign"
    expect_injected: bool
    notes: str = ""
    cls: Optional[str] = None       # attacks only
    technique: Optional[str] = None  # attacks only
    genre: Optional[str] = None      # benign only
    language: str = "en"
    hard: bool = False
    shard: str = ""

    @property
    def is_attack(self) -> bool:
        return self.label == "attack"

    @property
    def group(self) -> str:
        """The bucket this case is reported under: attack class or benign genre."""
        return self.cls or self.genre or "unknown"


class CorpusError(ValueError):
    """Raised when a corpus file is malformed. The corpus is a test fixture:
    a broken line is a build failure, never something to skip silently."""


def _case_from(obj: Dict[str, object], shard: str, line_no: int) -> Case:
    def need(field: str) -> object:
        if field not in obj:
            raise CorpusError(f"{shard}:{line_no}: missing required field {field!r}")
        return obj[field]

    label = str(need("label"))
    if label not in ("attack", "benign"):
        raise CorpusError(f"{shard}:{line_no}: label must be 'attack' or 'benign', got {label!r}")

    expect = need("expect_injected")
    if not isinstance(expect, bool):
        raise CorpusError(f"{shard}:{line_no}: expect_injected must be a boolean")
    if expect != (label == "attack"):
        raise CorpusError(
            f"{shard}:{line_no}: expect_injected={expect} contradicts label={label!r}"
        )

    text = str(need("text"))
    if len(text.strip()) < 20:
        raise CorpusError(f"{shard}:{line_no}: text is too short to be a realistic document")

    if label == "attack":
        cls = str(need("class"))
        if cls not in ATTACK_CLASSES:
            raise CorpusError(f"{shard}:{line_no}: unknown attack class {cls!r}")
        genre = None
        technique = str(need("technique"))
    else:
        cls = None
        technique = None
        genre = str(need("genre"))

    return Case(
        id=str(need("id")),
        text=text,
        label=label,
        expect_injected=expect,
        notes=str(obj.get("notes", "")),
        cls=cls,
        technique=technique,
        genre=genre,
        language=str(obj.get("language", "en")),
        hard=bool(obj.get("hard", False)),
        shard=shard,
    )


def iter_shard(path: Path) -> Iterator[Case]:
    with path.open(encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise CorpusError(f"{path.name}:{line_no}: invalid JSON: {exc}") from exc
            yield _case_from(obj, path.name, line_no)


def load(parts_dir: Path = PARTS_DIR) -> List[Case]:
    """Load every shard, in a stable order, rejecting duplicates."""
    if not parts_dir.is_dir():
        raise CorpusError(f"corpus directory not found: {parts_dir}")

    cases: List[Case] = []
    seen_ids: Dict[str, str] = {}
    seen_texts: Dict[str, str] = {}
    for path in sorted(parts_dir.glob("*.jsonl")):
        for case in iter_shard(path):
            if case.id in seen_ids:
                raise CorpusError(f"duplicate id {case.id!r} in {path.name} and {seen_ids[case.id]}")
            seen_ids[case.id] = path.name
            key = " ".join(case.text.split())
            if key in seen_texts:
                raise CorpusError(
                    f"duplicate text: {case.id!r} ({path.name}) repeats {seen_texts[key]!r}"
                )
            seen_texts[key] = case.id
            cases.append(case)

    if not cases:
        raise CorpusError(f"corpus is empty: {parts_dir}")
    return cases


def summary(cases: List[Case]) -> str:
    attacks = [c for c in cases if c.is_attack]
    benign = [c for c in cases if not c.is_attack]
    langs = sorted({c.language for c in cases})
    classes = sorted({c.group for c in attacks})
    genres = sorted({c.group for c in benign})
    return (
        f"{len(cases)} cases  ({len(attacks)} attack / {len(benign)} benign, "
        f"{sum(1 for c in cases if c.hard)} marked hard)\n"
        f"  languages ({len(langs)}): {', '.join(langs)}\n"
        f"  attack classes ({len(classes)}): {', '.join(classes)}\n"
        f"  benign genres ({len(genres)}): {', '.join(genres)}"
    )


def export_jsonl(cases: List[Case], path: Path) -> None:
    """Write the merged corpus as a single flat file — what the TS and Swift
    conformance drivers read, so every language grades the identical bytes."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for c in cases:
            fh.write(json.dumps({
                "id": c.id,
                "text": c.text,
                "label": c.label,
                "expect_injected": c.expect_injected,
                "class": c.cls,
                "technique": c.technique,
                "genre": c.genre,
                "language": c.language,
                "hard": c.hard,
            }, ensure_ascii=False, sort_keys=True) + "\n")


if __name__ == "__main__":  # pragma: no cover - developer convenience
    import sys

    cases = load()
    print(summary(cases))
    if "--export" in sys.argv:
        out = CORPUS_DIR / "corpus.jsonl"
        export_jsonl(cases, out)
        print(f"exported {len(cases)} cases → {out.relative_to(REPO_ROOT)}")
