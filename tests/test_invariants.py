import pytest

from invariants.runner import run_all


@pytest.mark.asyncio
async def test_security_invariants():
    findings = await run_all("invariants.yml")
    assert findings == [], "Invariant failures:\n" + "\n".join(
        f"- [{f.severity}] {f.check}: {f.message} ({f.evidence})" for f in findings
    )
