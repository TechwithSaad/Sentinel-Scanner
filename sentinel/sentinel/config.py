"""
sentinel/config.py

Loads optional .sentinel.yml configuration file.
Falls back to empty defaults if no config is found.
"""

from pathlib import Path
from typing import Optional

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


DEFAULT_CONFIG = {
    "exclude": [],
    "min_severity": None,
    "custom_rules": [],
}


def load_config(config_path: Optional[str] = None) -> dict:
    """
    Load configuration from a YAML file.

    Resolution order:
    1. Explicit --config path
    2. .sentinel.yml in current working directory
    3. Built-in defaults
    """
    if not YAML_AVAILABLE:
        return DEFAULT_CONFIG.copy()

    candidates = []
    if config_path:
        candidates.append(Path(config_path))
    candidates.append(Path.cwd() / ".sentinel.yml")

    for path in candidates:
        if path.exists():
            try:
                with path.open("r", encoding="utf-8") as fh:
                    data = yaml.safe_load(fh) or {}
                # Merge with defaults so missing keys are always present
                merged = DEFAULT_CONFIG.copy()
                merged.update({k: v for k, v in data.items() if v is not None})
                return merged
            except Exception as exc:
                print(f"[WARN] Could not parse config at {path}: {exc}")

    return DEFAULT_CONFIG.copy()
