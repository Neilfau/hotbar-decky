# Checks the release ZIP layout against what Decky's store CLI produces, and that packing is reproducible.
import json
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

import package  # noqa: E402


@pytest.fixture
def plugin_root(tmp_path):
    root = tmp_path / "src"
    root.mkdir()
    (root / "plugin.json").write_text(json.dumps({"name": "HotBar"}))
    for name in ("LICENSE", "README.md", "main.py", "package.json"):
        (root / name).write_text(name)
    (root / "decky.pyi").write_text("stub")
    (root / "dist").mkdir()
    (root / "dist" / "index.js").write_text("js")
    mod = root / "py_modules" / "hotbar"
    (mod / "__pycache__").mkdir(parents=True)
    (mod / "__init__.py").write_text("")
    (mod / "__pycache__" / "x.cpython-314.pyc").write_bytes(b"\0")
    (root / "defaults").mkdir()
    (root / "defaults" / "settings.json").write_text("{}")
    (root / "tests").mkdir()
    (root / "tests" / "test_x.py").write_text("")
    return root


def test_layout_matches_decky_cli(plugin_root, tmp_path):
    target = package.build(plugin_root, tmp_path / "out")
    assert target.name == "HotBar.zip"
    with zipfile.ZipFile(target) as zf:
        names = zf.namelist()
        modes = {i.filename: (i.external_attr >> 16) & 0o777 for i in zf.infolist()}
    assert names == sorted(names)
    assert set(names) == {
        "HotBar/LICENSE",
        "HotBar/README.md",
        "HotBar/dist/index.js",
        "HotBar/main.py",
        "HotBar/package.json",
        "HotBar/plugin.json",
        "HotBar/py_modules/hotbar/__init__.py",
        "HotBar/settings.json",
    }
    assert modes["HotBar/py_modules/hotbar/__init__.py"] == 0o755
    assert modes["HotBar/main.py"] == 0o644


def test_same_tree_gives_same_bytes(plugin_root, tmp_path):
    first = package.build(plugin_root, tmp_path / "a").read_bytes()
    (plugin_root / "main.py").touch()
    second = package.build(plugin_root, tmp_path / "b").read_bytes()
    assert first == second


def test_missing_build_output_stops(plugin_root, tmp_path):
    (plugin_root / "dist" / "index.js").unlink()
    with pytest.raises(SystemExit, match="dist/index.js"):
        package.build(plugin_root, tmp_path / "out")
