"""Shared loading for the cookbook tools: content files, schema, ATT&CK reference data, the threat profile."""
from __future__ import annotations

import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CONTENT_DIRS = (ROOT / "detections", ROOT / "hunts")
SCHEMA = ROOT / "schema" / "detection.schema.json"
ATTACK = ROOT / "data" / "attack-techniques.json"
PROFILE = ROOT / "profile" / "threat-profile.yml"
STATUS_ORDER = ["draft", "qa", "prod", "retired"]


def load_yaml(path: Path) -> dict:
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def content_files() -> list[Path]:
    out: list[Path] = []
    for d in CONTENT_DIRS:
        out += sorted(d.glob("*.yml"))
    return out


def load_content() -> list[tuple[Path, dict]]:
    return [(p, load_yaml(p)) for p in content_files()]


def load_schema() -> dict:
    return json.loads(SCHEMA.read_text(encoding="utf-8"))


def load_attack() -> dict:
    """{'tactics': {TAxxxx: name}, 'techniques': {Txxxx(.yyy): {'name', 'tactics': [TAxxxx]}}}"""
    return json.loads(ATTACK.read_text(encoding="utf-8"))


def load_profile() -> dict:
    return load_yaml(PROFILE)


def dump_yaml(data: dict, path: Path) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        yaml.safe_dump(data, fh, sort_keys=False, allow_unicode=True, width=120)
