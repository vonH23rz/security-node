from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTROLLER = ROOT / "scripts" / "security-node-controller.py"


def test_table_status_badges_match_confidence_pill_dimensions_without_resizing_confidence():
    source = CONTROLLER.read_text(encoding="utf-8")

    assert "Security Node table status pill sizing." in source
    assert "without changing the Security Confidence pill itself" in source

    assert ".expected-surface-status .badge," in source
    assert ".observed-result-state .badge {" in source
    assert "border-radius: 999px !important;" in source
    assert "display: inline-block !important;" in source
    assert "line-height: 1 !important;" in source
    assert "padding: 0.25rem 0.5rem !important;" in source
    assert "white-space: nowrap !important;" in source

    # The rejected broad override must stay out; the accepted XS typography
    # block may still target .badge and .confidence-badge for shared font size.
    assert "Security Node shared status pill sizing." not in source
    assert "Security Node confidence pill-only status styling." not in source
    assert "min-height: 1.35rem !important;" not in source
