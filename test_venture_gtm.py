import json
from pathlib import Path


def test_openapi_x402_spec_valid() -> None:
    spec = json.loads(Path('openapi_x402_spec.json').read_text(encoding='utf-8'))
    assert spec['openapi'] == '3.1.0'
    pay = spec['x-payment-x402']
    assert pay['asset'] == 'USDC'
    assert pay['evm_recipient'].startswith('0x')
