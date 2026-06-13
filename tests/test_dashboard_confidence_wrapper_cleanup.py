from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTROLLER = ROOT / "scripts" / "security-node-controller.py"


def test_security_confidence_wrapper_has_no_state_background_class():
    source = CONTROLLER.read_text(encoding="utf-8")

    # The outer status strip remains the confidence/state indicator; the
    # confidence badge remains the only filled element inside the Security
    # Confidence text group.
    assert "status-strip-confidence-" in source
    assert "confidence_class(state.security_confidence)" in source
    assert '<section class="security-status-strip {security_status_strip_class}" aria-label="Security Node status summary">' in source
    assert "border-left: 0.4rem solid #b3b6b6;" in source
    assert 'class="security-confidence" aria-label="Security Confidence: {security_confidence_text}"' in source
    assert 'class="security-confidence {security_confidence_class}"' not in source
    assert "security_confidence_class =" not in source
    assert '<span class="confidence-badge {escaped_class}">{escaped_confidence}</span>' in source
