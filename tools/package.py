# Packs the built plugin into the ZIP layout Decky's store CLI produces, for "install from ZIP" and releases.
#
#   python3 tools/package.py [--root DIR] [--out DIR]
#
# Run `pnpm run build` first (or `pnpm run package`, which does both). The archive is out/<name>.zip with one
# top-level folder named after plugin.json's "name", holding LICENSE, README.md, main.py, package.json,
# plugin.json, any other top-level *.py, dist/, py_modules/ (without __pycache__), and bin/ and the contents of
# defaults/ when they exist. This mirrors `decky plugin build` (SteamDeckHomebrew/cli, zip_plugin). Entries are
# sorted and carry a fixed timestamp, so the same tree always gives the same bytes.
import argparse
import json
import sys
import zipfile
from pathlib import Path

REQUIRED_FILES = ("LICENSE", "README.md", "main.py", "package.json", "plugin.json")
FIXED_TIME = (1980, 1, 1, 0, 0, 0)
FILE_MODE = 0o644
EXEC_MODE = 0o755


def collect(root: Path) -> list[tuple[str, Path, int]]:
    """Returns (path inside the plugin folder, source file, mode) for every file to pack, sorted by path."""
    missing = [name for name in REQUIRED_FILES if not (root / name).is_file()]
    if not (root / "dist" / "index.js").is_file():
        missing.append("dist/index.js")
    if missing:
        raise SystemExit(f"package: missing {', '.join(missing)} (run `pnpm run build` first)")

    entries: dict[str, tuple[Path, int]] = {}
    for name in REQUIRED_FILES:
        entries[name] = (root / name, FILE_MODE)
    for py in root.glob("*.py"):
        entries[py.name] = (py, FILE_MODE)
    for folder, mode in (("dist", FILE_MODE), ("bin", EXEC_MODE), ("py_modules", EXEC_MODE)):
        for path in _files(root / folder):
            entries[path.relative_to(root).as_posix()] = (path, mode)
    defaults = root / "defaults"
    for path in _files(defaults):
        entries[path.relative_to(defaults).as_posix()] = (path, FILE_MODE)
    return sorted((name, src, mode) for name, (src, mode) in entries.items())


def _files(folder: Path) -> list[Path]:
    if not folder.is_dir():
        return []
    return [
        p for p in folder.rglob("*")
        if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc" and p.name != ".DS_Store"
    ]


def build(root: Path, out_dir: Path) -> Path:
    name = json.loads((root / "plugin.json").read_text())["name"]
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / f"{name}.zip"
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for rel, src, mode in collect(root):
            info = zipfile.ZipInfo(f"{name}/{rel}", FIXED_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o100000 | mode) << 16
            info.create_system = 3
            zf.writestr(info, src.read_bytes(), compresslevel=9)
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Pack the built plugin into a Decky ZIP.")
    repo = Path(__file__).resolve().parent.parent
    parser.add_argument("--root", type=Path, default=repo, help="plugin folder (default: this repository)")
    parser.add_argument("--out", type=Path, default=repo / "out", help="output folder (default: out/)")
    args = parser.parse_args(argv)
    target = build(args.root.resolve(), args.out.resolve())
    print(target)
    return 0


if __name__ == "__main__":
    sys.exit(main())
