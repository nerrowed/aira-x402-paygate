"""Aira x402 PayGate: Zero-Dependency HTTP 402 USDC Middleware & Verifier for Python AI Agents - Zero-dependency HTTP 402 / x402 USDC payment gate & verifier for Python AI Agents."""
from __future__ import annotations

from aira_x402_paygate.core import (
    PaymentChallenge,
    PaymentReceipt,
    X402PayGate,
    X402ASGIMiddleware,
    is_valid_evm_address,
    is_valid_solana_address,
)

__version__ = "0.1.0"
__all__ = [
    "PaymentChallenge",
    "PaymentReceipt",
    "X402PayGate",
    "X402ASGIMiddleware",
    "is_valid_evm_address",
    "is_valid_solana_address",
    "__version__",
]
