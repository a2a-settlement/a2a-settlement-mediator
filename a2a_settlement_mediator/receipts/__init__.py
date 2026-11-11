"""Proof-of-fix receipt signing: DSSE envelopes, in-toto statements, and SLSA VSAs.

This package builds and signs receipts. It does not store them, serve them,
or talk to a timestamp authority.
"""

from a2a_settlement_mediator.receipts.dsse import (
    IN_TOTO_PAYLOAD_TYPE,
    DsseVerificationError,
    pae,
    sign_envelope,
    verify_envelope,
)
from a2a_settlement_mediator.receipts.predicate import (
    HOUSE_INDEPENDENCE_STATEMENT,
    IN_TOTO_STATEMENT_TYPE,
    PROOF_OF_FIX_PREDICATE_TYPE,
    Independence,
    ProofOfFixDraft,
    ProofOfFixPredicate,
    ProofOfFixStatement,
    SolverKind,
    Verdict,
    VexStatus,
    build_proof_of_fix_statement,
    canonical_json_bytes,
)
from a2a_settlement_mediator.receipts.signer import (
    JwkError,
    KmsKeySpecError,
    KmsSigner,
    LocalSigner,
    Signer,
    SigningConfigError,
    signer_from_settings,
)
from a2a_settlement_mediator.receipts.vsa import (
    POLICY_URI,
    VSA_PREDICATE_TYPE,
    VerificationResult,
    VsaStatement,
    build_vsa,
)

__all__ = [
    "DsseVerificationError",
    "HOUSE_INDEPENDENCE_STATEMENT",
    "IN_TOTO_PAYLOAD_TYPE",
    "IN_TOTO_STATEMENT_TYPE",
    "Independence",
    "JwkError",
    "KmsKeySpecError",
    "KmsSigner",
    "LocalSigner",
    "POLICY_URI",
    "PROOF_OF_FIX_PREDICATE_TYPE",
    "ProofOfFixDraft",
    "ProofOfFixPredicate",
    "ProofOfFixStatement",
    "Signer",
    "SigningConfigError",
    "SolverKind",
    "VSA_PREDICATE_TYPE",
    "VerificationResult",
    "Verdict",
    "VexStatus",
    "VsaStatement",
    "build_proof_of_fix_statement",
    "build_vsa",
    "canonical_json_bytes",
    "pae",
    "sign_envelope",
    "signer_from_settings",
    "verify_envelope",
]
