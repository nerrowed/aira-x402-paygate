"""CLI utility for issuing & verifying x402 USDC payment headers."""
from __future__ import annotations

import argparse
import json
from aira_x402_paygate.core import X402PayGate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog='x402-gate', description='Issue and verify HTTP 402 USDC challenges')
    parser.add_argument('--evm', default='0xD1d2b5a2665C75fb80Fb069Ce04D1fe711a2B349')
    parser.add_argument('--solana', default='BgagbXYr125qDFic7cp73SxuSXkwGiUVU7RqnbQD8Ffe')
    parser.add_argument('--secret', default='aira-x402-demo-secret-key')
    parser.add_argument('--resource', default='/api/paid/intel')
    parser.add_argument('--price', type=float, default=0.95)
    args = parser.parse_args(argv)
    gate = X402PayGate(pay_to_evm=args.evm, pay_to_solana=args.solana, signing_secret=args.secret, default_price_usdc=args.price)
    ch = gate.issue_challenge(args.resource)
    print(json.dumps(ch.to_http_402_payload(), indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
