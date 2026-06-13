from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTROLLER = ROOT / "scripts" / "security-node-controller.py"


def test_security_node_uses_sanity_xs_typography_sizing_baseline():
    source = CONTROLLER.read_text(encoding="utf-8")

    assert "Security Node shared XS typography sizing baseline" in source
    assert "Matches the Sanity Node Variant XS compact dashboard sizing" in source

    # Keep Security Node aligned with Sanity Node XS compact sizing.
    assert "font-size: 12px !important;" in source
    assert "line-height: 1.29 !important;" in source
    assert "font-size: 22px !important;" in source
    assert "line-height: 1.12 !important;" in source
    assert "font-size: 15.5px !important;" in source
    assert "line-height: 1.22 !important;" in source
    assert "font-size: 10px !important;" in source
    assert "font-size: 9.5px !important;" in source

    # This slice must preserve the existing shared color/family foundation.
    assert "--vonh-text: #53585f;" in source
    assert 'font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;' in source
