"""Structured security observations."""

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Finding:
    check: str
    severity: str
    detail: str
    recommendation: str
    evidence: dict[str, str | int] | None = None

    def to_dict(self) -> dict:
        result = asdict(self)
        if self.evidence is None:
            result.pop("evidence")
        return result
