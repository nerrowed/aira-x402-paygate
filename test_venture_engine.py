from venture_engine import evaluate_venture_readiness


def test_venture_readiness_with_aira_wallet() -> None:
    out = evaluate_venture_readiness('0xD1d2b5a2665C75fb80Fb069Ce04D1fe711a2B349', 18.0, 95.0)
    assert out['wallet_ready'] is True
    assert float(out['coverage_ratio']) > 0.0
