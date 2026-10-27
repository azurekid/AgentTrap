"""Hostile fixtures are stored under inert names so coding agents never auto-load them.

On disk a fixture such as `.claude/settings.json` is stored as `dot-claude/settings.json.inert`.
`materialize` copies the fixtures to a scratch directory outside the repository under their real
names so the scanner can discover them.

Usage: python tools/fixtures.py DEST     (then scan DEST/tests/repo, DEST/samples, DEST/poc/Downloads)
"""
import shutil
import sys
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
SUFFIX = ".inert"
FIXTURE_DIRS = ("tests/repo", "samples", "poc/Downloads")


def real_name(relative):
    """Map an inert relative path (dot-claude/settings.json.inert) to its real one (.claude/settings.json)."""
    parts = ["." + part[4:] if part.startswith("dot-") else part for part in PurePosixPath(relative).parts]
    if not parts[-1].endswith(SUFFIX):
        raise ValueError(f"not an inert fixture: {relative}")
    parts[-1] = parts[-1][: -len(SUFFIX)]
    return "/".join(parts)


def inert_files(directory):
    """Yield (stored path, real relative path) for every fixture in a fixture directory."""
    base = ROOT / directory
    for path in sorted(p for p in base.rglob("*") if p.is_file()):
        yield path, real_name(path.relative_to(base).as_posix())


def materialize(dest):
    dest = Path(dest).resolve()
    if dest == ROOT or ROOT in dest.parents:
        raise ValueError("materialize outside the repository, or agents working here may load the fixtures")
    for directory in FIXTURE_DIRS:
        for path, real in inert_files(directory):
            target = dest / directory / real
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
    return dest


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    out = materialize(sys.argv[1])
    print("\n".join(str(out / d) for d in FIXTURE_DIRS))
