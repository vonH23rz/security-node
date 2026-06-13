from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTROLLER = ROOT / "scripts" / "security-node-controller.py"


def test_table_status_badges_are_compacted_without_resizing_confidence_badge():
    source = CONTROLLER.read_text(encoding="utf-8")

    assert "Security Node compact table status pill sizing." in source
    assert "Keep Security Confidence unchanged" in source

    assert ".expected-surface-status .badge," in source
    assert ".observed-result-state .badge {" in source
    assert "font-size: 8px !important;" in source
    assert "border-radius: 999px !important;" in source
    assert "display: inline-block !important;" in source
    assert "line-height: 1 !important;" in source
    assert "padding: 0.10rem 0.30rem !important;" in source
    assert "white-space: nowrap !important;" in source

    # Keep rejected experiments out.
    assert "Security Node shared status pill sizing." not in source
    assert "Security Node confidence pill-only status styling." not in source
    assert "font-size: 9px !important;" not in source
    assert "padding: 0.16rem 0.42rem !important;" not in source
    assert "padding: 0.25rem 0.5rem !important;" not in source
    assert "min-height: 1.35rem !important;" not in source
