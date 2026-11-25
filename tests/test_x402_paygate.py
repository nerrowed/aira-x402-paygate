import asyncio
import base64
import json
from aira_x402_paygate import X402ASGIMiddleware, X402PayGate, is_valid_evm_address, is_valid_solana_address


def test_address_validators() -> None:
    assert is_valid_evm_address('0xD1d2b5a2665C75fb80Fb069Ce04D1fe711a2B349') is True
    assert is_valid_evm_address('invalid') is False
    assert is_valid_solana_address('BgagbXYr125qDFic7cp73SxuSXkwGiUVU7RqnbQD8Ffe') is True


def test_issue_and_verify_x402_payment_and_replay_protection() -> None:
    gate = X402PayGate(
        pay_to_evm='0xD1d2b5a2665C75fb80Fb069Ce04D1fe711a2B349',
        pay_to_solana='BgagbXYr125qDFic7cp73SxuSXkwGiUVU7RqnbQD8Ffe',
        signing_secret='super-secret-signing-key-2026',
        default_price_usdc=0.95,
    )
    ch = gate.issue_challenge('/api/paid/intel', now_ts=1_700_000_000)
    receipt = {
        'invoice_id': ch.invoice_id,
        'tx_hash': '0x' + 'ab' * 32,
        'chain': 'base',
        'amount_usdc': 0.95,
        'signature': ch.signature,
    }
    hdr = base64.urlsafe_b64encode(json.dumps(receipt).encode('utf-8')).decode('ascii')
    ok, reason, parsed = gate.verify_payment(
        hdr,
        resource='/api/paid/intel',
        expected_amount_usdc=0.95,
        expires_at=ch.expires_at,
        now_ts=1_700_000_050,
    )
    assert ok is True and reason == 'verified' and parsed is not None
    ok_replay, reason_replay, _ = gate.verify_payment(
        hdr,
        resource='/api/paid/intel',
        expected_amount_usdc=0.95,
        expires_at=ch.expires_at,
        now_ts=1_700_000_055,
    )
    assert ok_replay is False and reason_replay == 'replay_tx_hash_detected'


def test_asgi_middleware_blocks_unpaid_with_402_and_allows_paid() -> None:
    gate = X402PayGate(
        pay_to_evm='0xD1d2b5a2665C75fb80Fb069Ce04D1fe711a2B349',
        signing_secret='super-secret-signing-key-2026',
        default_price_usdc=0.25,
    )
    async def inner_app(scope, receive, send):
        await send({'type': 'http.response.start', 'status': 200, 'headers': []})
        await send({'type': 'http.response.body', 'body': b'ok'})
    mw = X402ASGIMiddleware(inner_app, gate, protected_prefixes=('/api/paid',))
    sent_unpaid = []
    async def send_u(msg): sent_unpaid.append(msg)
    asyncio.run(mw({'type': 'http', 'path': '/api/paid/feed', 'headers': []}, None, send_u))
    assert sent_unpaid[0]['status'] == 402
    receipt = base64.urlsafe_b64encode(json.dumps({
        'invoice_id': 'x402-live', 'tx_hash': '0x' + 'cd' * 32, 'chain': 'base', 'amount_usdc': 0.25
    }).encode('utf-8')).decode('ascii')
    sent_paid = []
    async def send_p(msg): sent_paid.append(msg)
    asyncio.run(mw({'type': 'http', 'path': '/api/paid/feed', 'headers': [(b'x-payment', receipt.encode())]}, None, send_p))
    assert sent_paid[0]['status'] == 200
