"""Persistent application data storage with non-destructive legacy migration."""

from __future__ import annotations

import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path


APP_DATA_NAME = "MalApp_AgentTrace_LearningLoop"
MIGRATION_MARKER = ".shared_data_migration.json"


def _unique_paths(paths: list[Path]) -> list[Path]:
    result: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        try:
            key = str(path.resolve()).lower()
        except OSError:
            key = str(path).lower()
        if key not in seen:
            seen.add(key)
            result.append(path)
    return result


def _application_roots() -> list[Path]:
    roots = [Path(__file__).resolve().parent, Path.cwd()]
    if getattr(sys, "frozen", False):
        roots.insert(0, Path(sys.executable).resolve().parent)
        bundle_root = getattr(sys, "_MEIPASS", None)
        if bundle_root:
            roots.append(Path(bundle_root))
    return _unique_paths(roots)


def _legacy_data_dirs() -> list[Path]:
    candidates: list[Path] = []
    for root in _application_roots():
        candidates.append(root / "data")
        release_root = root if root.name.lower() == "release" else root / "release"
        if release_root.is_dir():
            try:
                candidates.extend(child / "data" for child in release_root.iterdir() if child.is_dir())
            except OSError:
                pass
    return [path for path in _unique_paths(candidates) if path.is_dir()]


def _legacy_score(data_dir: Path) -> tuple[int, int, float]:
    files = []
    try:
        files = [path for path in data_dir.rglob("*") if path.is_file()]
    except OSError:
        return (0, 0, 0.0)
    report_files = sum(1 for path in files if any(token in path.name.lower() for token in ("report", "cache", "result", "memory", "sqlite", "db")))
    total_size = sum(path.stat().st_size for path in files if path.exists())
    newest = max((path.stat().st_mtime for path in files if path.exists()), default=0.0)
    return (report_files * 1000 + len(files), total_size, newest)


def _copy_legacy_data(source: Path, target: Path) -> int:
    copied = 0
    for item in source.rglob("*"):
        if not item.is_file():
            continue
        relative = item.relative_to(source)
        destination = target / relative
        if destination.exists():
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(item, destination)
        copied += 1
    return copied


def _shared_data_dir() -> Path:
    configured = os.environ.get("MALAPP_DATA_DIR")
    if configured:
        return Path(configured).expanduser()
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / APP_DATA_NAME / "data"


def resolve_data_dir() -> Path:
    """Return the persistent data directory and migrate the best legacy release once."""
    target = _shared_data_dir()
    target.mkdir(parents=True, exist_ok=True)
    marker = target / MIGRATION_MARKER
    if marker.exists() or os.environ.get("MALAPP_DATA_DIR"):
        return target

    candidates = [path for path in _legacy_data_dirs() if path.resolve() != target.resolve()]
    source = max(candidates, key=_legacy_score, default=None)
    copied = 0
    if source and _legacy_score(source)[0] > 0:
        copied = _copy_legacy_data(source, target)
    marker.write_text(
        json.dumps(
            {
                "migrated_at": datetime.now(timezone.utc).isoformat(),
                "source": str(source) if source else None,
                "copied_files": copied,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    return target
