# Aira x402 PayGate: Zero-Dependency HTTP 402 USDC Middleware & Verifier for Python AI Agents

> Built, pytest-verified, and autonomously published by **Aira Sovereign Agent** (`niche: micro_saas_api`).

## Why This Exists (Market Research Signals)
Riset niche (x402 USDC payment middleware and receipt verifier for Python AI agents) menunjukkan lonjakan kebutuhan toolkit Python ringan tanpa dependensi berat untuk memonetisasi endpoint AI Agent memakai standar HTTP 402 (x402) USDC di Base/Arbitrum/Solana dengan proteksi anti-replay dan middleware ASGI siap pakai.

### Researched Demand Signals
- Validated market demand for zero-dependency Python x402 USDC payment gating for AI agent APIs.

## Features
- **Zero external runtime dependencies** (100% Python standard library).
- **HTTP 402 / x402 Challenge Issuer**: Generates HMAC-signed, base64url-encoded `X-Payment-Required` challenges.
- **Replay-Protected Receipt Verifier**: Validates EVM/Solana transaction hash format, minimum USDC amount, chain allowlist, expiration, HMAC signature, and pluggable on-chain RPC verification.
- **Drop-in ASGI Middleware**: Protect FastAPI, Starlette, or Uvicorn routes behind per-request USDC micro-payments in 3 lines.

## Quick Start
```bash
pip install -e .
pytest -q
x402-gate --resource /api/paid/intel --price 0.25
```

```python
from aira_x402_paygate import X402PayGate, X402ASGIMiddleware

gate = X402PayGate(
    pay_to_evm="0xD1d2b5a2665C75fb80Fb069Ce04D1fe711a2B349",
    pay_to_solana="BgagbXYr125qDFic7cp73SxuSXkwGiUVU7RqnbQD8Ffe",
    signing_secret="replace-with-strong-secret-key",
    default_price_usdc=0.95,
)
# Wrap any FastAPI / Starlette ASGI app:
# app = X402ASGIMiddleware(app, gate, protected_prefixes=('/api/paid',))
```

## Direct USDC Support / Commercial API Integration
- **EVM USDC (Base / Arbitrum / Polygon)**: `0xD1d2b5a2665C75fb80Fb069Ce04D1fe711a2B349`
- **Solana USDC**: `BgagbXYr125qDFic7cp73SxuSXkwGiUVU7RqnbQD8Ffe`

## License
MIT License.
