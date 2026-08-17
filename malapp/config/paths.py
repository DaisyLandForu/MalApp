"""Project and runtime data paths.

The refactored project has one explicit runtime data directory.  No legacy
desktop-release discovery or automatic migration is performed.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULTS_DIR = Path(__file__).resolve().parent / "defaults"
DEFAULT_DATA_DIR = PROJECT_ROOT / "data"
DEFAULT_WORKSPACE_DIR = PROJECT_ROOT / "workspace"

RUNTIME_SEED_FILES = (
    "schema.json",
    "field_mapping.json",
    "sample_conflict.json",
    "eval/best_params.json",
)


def resolve_data_dir() -> Path:
    """Return the configured runtime data directory without legacy probing."""
    return Path(os.getenv("MALAPP_DATA_DIR", str(DEFAULT_DATA_DIR))).expanduser().resolve()


def resolve_workspace_dir() -> Path:
    """Return the only directory from which local sample paths may be read."""
    return Path(
        os.getenv("MALAPP_WORKSPACE_ROOT", str(DEFAULT_WORKSPACE_DIR))
    ).expanduser().resolve()


def initialize_runtime_files(data_dir: Path | None = None) -> Path:
    """Seed versioned defaults into an empty runtime directory.

    Existing runtime files are never overwritten.
    """
    target = (data_dir or resolve_data_dir()).resolve()
    target.mkdir(parents=True, exist_ok=True)
    for relative_name in RUNTIME_SEED_FILES:
        source = DEFAULTS_DIR / relative_name
        destination = target / relative_name
        if not source.is_file():
            raise FileNotFoundError(f"missing packaged runtime default: {source}")
        if destination.exists():
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    return target
