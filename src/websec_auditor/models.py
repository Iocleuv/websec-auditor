from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Finding:
    check: str
    severity: str
    detail: str
    recommendation: str

    def to_dict(self) -> dict:
        return asdict(self)
