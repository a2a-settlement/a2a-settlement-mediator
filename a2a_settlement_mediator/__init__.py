"""A2A Settlement Mediator — AI-powered dispute resolution for the A2A Settlement Exchange."""

from a2a_settlement_mediator.config import MediatorSettings, settings
from a2a_settlement_mediator.evidence import collect_evidence
from a2a_settlement_mediator.mediator import mediate
from a2a_settlement_mediator.schemas import (
    AuditRecord,
    EvidenceBundle,
    Resolution,
    Verdict,
    VerdictOutcome,
)

__all__ = [
    "mediate",
    "collect_evidence",
    "settings",
    "MediatorSettings",
    "AuditRecord",
    "EvidenceBundle",
    "Resolution",
    "Verdict",
    "VerdictOutcome",
]

__version__ = "0.1.0"
