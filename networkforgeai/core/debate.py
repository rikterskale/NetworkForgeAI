"""Bounded, advisory multi-agent debate coordination."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Protocol, Sequence


class DebateParticipant(Protocol):
    """Minimal interface required by the debate coordinator."""

    id: str

    async def analyze_context(self, prompt: str, context: dict[str, Any]) -> Any: ...


@dataclass(frozen=True)
class DebateOpinion:
    """One bounded, advisory response from a participant."""

    participant_id: str
    round_number: int
    content: str
    error: str | None = None


@dataclass(frozen=True)
class DebateResult:
    """Collected opinions and critiques; no action is selected automatically."""

    opinions: tuple[DebateOpinion, ...]
    critiques: tuple[DebateOpinion, ...]

    @property
    def errors(self) -> tuple[DebateOpinion, ...]:
        return tuple(item for item in (*self.opinions, *self.critiques) if item.error)


class MultiAgentDebate:
    """Run a small independent-analysis and peer-critique exchange.

    The coordinator only calls ``analyze_context``. It never executes tools,
    changes the knowledge base, requests approval, or chooses a winner.
    """

    def __init__(self, *, max_participants: int = 3, max_rounds: int = 2, max_chars: int = 2000):
        if max_participants <= 0 or max_rounds <= 0 or max_chars <= 0:
            raise ValueError("debate limits must be positive")
        self.max_participants = max_participants
        self.max_rounds = min(max_rounds, 2)
        self.max_chars = max_chars

    async def run(
        self,
        prompt: str,
        context: dict[str, Any],
        participants: Sequence[DebateParticipant],
        *,
        rounds: int | None = None,
    ) -> DebateResult:
        """Collect independent opinions and, optionally, one critique round."""
        selected = tuple(participants[: self.max_participants])
        if not selected:
            return DebateResult(opinions=(), critiques=())
        round_limit = self.max_rounds if rounds is None else min(rounds, self.max_rounds)
        if round_limit <= 0:
            return DebateResult(opinions=(), critiques=())

        opinions = tuple(
            await asyncio.gather(
                *(self._ask(participant, prompt, context, 1) for participant in selected)
            )
        )
        if round_limit == 1:
            return DebateResult(opinions=opinions, critiques=())

        peer_digest = "\n".join(
            f"- {opinion.participant_id}: {opinion.content}"
            for opinion in opinions
            if opinion.content
        )[: self.max_chars]
        critique_prompt = (
            f"{prompt}\nPeer analyses to critique:\n{peer_digest}\n"
            "Identify agreements, disagreements, and evidence gaps. Do not authorize actions."
        )
        critiques = tuple(
            await asyncio.gather(
                *(self._ask(participant, critique_prompt, context, 2) for participant in selected)
            )
        )
        return DebateResult(opinions=opinions, critiques=critiques)

    async def _ask(
        self,
        participant: DebateParticipant,
        prompt: str,
        context: dict[str, Any],
        round_number: int,
    ) -> DebateOpinion:
        try:
            response = await participant.analyze_context(prompt, context)
            content = str(getattr(response, "content", response))[: self.max_chars]
            return DebateOpinion(participant.id, round_number, content)
        except Exception as exc:  # pragma: no cover - defensive provider boundary
            return DebateOpinion(participant.id, round_number, "", type(exc).__name__)
