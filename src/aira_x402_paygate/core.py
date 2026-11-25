"""Zero-dependency HTTP 402 (x402) USDC payment challenge, receipt verification, and ASGI middleware."""
from __future__ import annotations

import base64
from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import re
import time
import uuid
from typing import Any, Awaitable, Callable

_EVM_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_SOL_ADDR_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")
_TX_HASH_RE = re.compile(r"^(0x[0-9a-fA-F]{64}|[1-9A-HJ-NP-Za-km-z]{64,90})$")


def is_valid_evm_address(address: str) -> bool:
    return bool(_EVM_ADDR_RE.match(str(address or '').strip()))


def is_valid_solana_address(address: str) -> bool:
    return bool(_SOL_ADDR_RE.match(str(address or '').strip()))


def is_valid_tx_hash(tx_hash: str) -> bool:
    return bool(_TX_HASH_RE.match(str(tx_hash or '').strip()))


@dataclass(frozen=True)
class PaymentChallenge:
    invoice_id: str
    resource: str
    amount_usdc: float
    asset: str
    chains: tuple[str, ...]
    pay_to_evm: str
    pay_to_solana: str
    expires_at: int
    signature: str

    def to_header_value(self) -> str:
        raw = json.dumps(asdict(self), separators=(',', ':'), sort_keys=True).encode('utf-8')
        return base64.urlsafe_b64encode(raw).decode('ascii')

    def to_http_402_payload(self) -> dict[str, Any]:
        return {
            'error': 'payment_required',
            'protocol': 'x402',
            'challenge': asdict(self),
            'instructions': (
                f'Send {self.amount_usdc:.4f} {self.asset} on {self.chains[0]} to {self.pay_to_evm} '
                'and retry with header X-Payment: <base64-json-receipt>'
            ),
        }


@dataclass(frozen=True)
class PaymentReceipt:
    invoice_id: str
    tx_hash: str
    chain: str
    amount_usdc: float
    payer: str = ''
    signature: str = ''


class X402PayGate:
    """Stateless HMAC-signed x402 invoice issuer & idempotent receipt verifier."""

    def __init__(
        self,
        *,
        pay_to_evm: str,
        pay_to_solana: str = '',
        signing_secret: str,
        default_price_usdc: float = 0.25,
        chains: tuple[str, ...] = ('base', 'arbitrum', 'solana'),
        ttl_seconds: int = 900,
        onchain_verifier: Callable[[PaymentReceipt, str], bool] | None = None,
    ) -> None:
        if not is_valid_evm_address(pay_to_evm):
            raise ValueError('pay_to_evm must be a valid 0x EVM address')
        if pay_to_solana and not is_valid_solana_address(pay_to_solana):
            raise ValueError('pay_to_solana must be a valid Solana Base58 address')
        if not signing_secret or len(signing_secret) < 12:
            raise ValueError('signing_secret must be at least 12 characters')
        self.pay_to_evm = pay_to_evm
        self.pay_to_solana = pay_to_solana
        self._secret = signing_secret.encode('utf-8')
        self.default_price_usdc = round(max(0.0001, float(default_price_usdc)), 6)
        self.chains = tuple(c.strip().lower() for c in chains if c.strip()) or ('base',)
        self.ttl_seconds = max(30, int(ttl_seconds))
        self._onchain_verifier = onchain_verifier
        self._consumed_tx_hashes: set[str] = set()

    def _sign_fields(self, invoice_id: str, resource: str, amount_usdc: float, expires_at: int) -> str:
        msg = f'{invoice_id}|{resource}|{amount_usdc:.6f}|{expires_at}|{self.pay_to_evm}'.encode('utf-8')
        return hmac.new(self._secret, msg, hashlib.sha256).hexdigest()[:32]

    def issue_challenge(self, resource: str, *, price_usdc: float | None = None, now_ts: int | None = None) -> PaymentChallenge:
        now = int(now_ts if now_ts is not None else time.time())
        amt = round(max(0.0001, float(price_usdc if price_usdc is not None else self.default_price_usdc)), 6)
        inv_id = f'x402-{uuid.uuid4().hex[:14]}'
        exp = now + self.ttl_seconds
        sig = self._sign_fields(inv_id, resource, amt, exp)
        return PaymentChallenge(
            invoice_id=inv_id,
            resource=resource,
            amount_usdc=amt,
            asset='USDC',
            chains=self.chains,
            pay_to_evm=self.pay_to_evm,
            pay_to_solana=self.pay_to_solana,
            expires_at=exp,
            signature=sig,
        )

    @staticmethod
    def decode_payment_header(header_value: str) -> PaymentReceipt:
        raw = str(header_value or '').strip()
        if not raw:
            raise ValueError('Empty X-Payment header')
        if raw.startswith('{'):
            data = json.loads(raw)
        else:
            pad = '=' * (-len(raw) % 4)
            data = json.loads(base64.urlsafe_b64decode(raw + pad).decode('utf-8'))
        return PaymentReceipt(
            invoice_id=str(data.get('invoice_id') or '').strip(),
            tx_hash=str(data.get('tx_hash') or '').strip(),
            chain=str(data.get('chain') or 'base').strip().lower(),
            amount_usdc=float(data.get('amount_usdc') or 0.0),
            payer=str(data.get('payer') or '').strip(),
            signature=str(data.get('signature') or '').strip(),
        )

    def verify_payment(
        self,
        header_value: str,
        *,
        resource: str,
        expected_amount_usdc: float | None = None,
        expires_at: int | None = None,
        now_ts: int | None = None,
    ) -> tuple[bool, str, PaymentReceipt | None]:
        now = int(now_ts if now_ts is not None else time.time())
        try:
            receipt = self.decode_payment_header(header_value)
        except Exception as exc:
            return False, f'invalid_payment_header: {exc}', None
        min_amt = float(expected_amount_usdc if expected_amount_usdc is not None else self.default_price_usdc)
        if receipt.chain not in self.chains:
            return False, f'unsupported_chain: {receipt.chain}', receipt
        if not is_valid_tx_hash(receipt.tx_hash):
            return False, 'invalid_tx_hash_format', receipt
        if receipt.amount_usdc + 1e-9 < min_amt:
            return False, f'underpaid: got {receipt.amount_usdc} < {min_amt}', receipt
        if receipt.tx_hash.lower() in self._consumed_tx_hashes:
            return False, 'replay_tx_hash_detected', receipt
        if expires_at is not None:
            if now > int(expires_at):
                return False, 'invoice_expired', receipt
            expected_sig = self._sign_fields(receipt.invoice_id, resource, min_amt, int(expires_at))
            if not hmac.compare_digest(receipt.signature, expected_sig):
                return False, 'invalid_invoice_signature', receipt
        if self._onchain_verifier is not None:
            recipient = self.pay_to_solana if receipt.chain == 'solana' else self.pay_to_evm
            if not bool(self._onchain_verifier(receipt, recipient)):
                return False, 'onchain_verification_failed', receipt
        self._consumed_tx_hashes.add(receipt.tx_hash.lower())
        return True, 'verified', receipt


class X402ASGIMiddleware:
    """Drop-in ASGI middleware (FastAPI / Starlette / Uvicorn) gating paths with HTTP 402 USDC."""

    def __init__(
        self,
        app: Callable[..., Awaitable[Any]],
        gate: X402PayGate,
        *,
        protected_prefixes: tuple[str, ...] = ('/api/paid',),
    ) -> None:
        self.app = app
        self.gate = gate
        self.protected_prefixes = protected_prefixes

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get('type') != 'http':
            await self.app(scope, receive, send)
            return
        path = str(scope.get('path') or '/')
        if not any(path.startswith(p) for p in self.protected_prefixes):
            await self.app(scope, receive, send)
            return
        hdrs = {k.decode('latin-1').lower(): v.decode('latin-1') for k, v in (scope.get('headers') or [])}
        payment_hdr = hdrs.get('x-payment', '')
        if payment_hdr:
            ok, reason, _ = self.gate.verify_payment(payment_hdr, resource=path)
            if ok:
                await self.app(scope, receive, send)
                return
            err_body = json.dumps({'error': 'payment_rejected', 'reason': reason}).encode('utf-8')
            await send({'type': 'http.response.start', 'status': 402, 'headers': [(b'content-type', b'application/json')]})
            await send({'type': 'http.response.body', 'body': err_body})
            return
        challenge = self.gate.issue_challenge(path)
        body = json.dumps(challenge.to_http_402_payload()).encode('utf-8')
        await send({
            'type': 'http.response.start',
            'status': 402,
            'headers': [
                (b'content-type', b'application/json'),
                (b'x-payment-required', challenge.to_header_value().encode('ascii')),
            ],
        })
        await send({'type': 'http.response.body', 'body': body})
