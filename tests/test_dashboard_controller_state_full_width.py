from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTROLLER = ROOT / "scripts" / "security-node-controller.py"


def test_controller_state_is_full_width_with_five_cards():
    source = CONTROLLER.read_text(encoding="utf-8")

    assert "Security Node full-width Controller State layout." in source
    assert ".controller-state-section," in source
    assert ".configuration-summary-section" in source
    assert "grid-column: 1 / -1;" in source
    assert ".controller-state-list" in source
    assert "grid-template-columns: repeat(5, minmax(0, 1fr));" in source

    # Keep this as a layout-only slice; typography baseline remains separate.
    assert "Security Node shared XS typography sizing baseline" in source
    assert "font-size: 12px !important;" in source
