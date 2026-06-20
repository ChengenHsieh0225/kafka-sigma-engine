"""Sigma Rule loader for the Kafka Sigma Engine."""

from pathlib import Path
from typing import Any

import yaml

from src.models import SigmaRule
from src.rule_engine.service import _build_rule


def load_rules(rules_dir: Path) -> list[SigmaRule]:
    """Load all Sigma Rule YAML files from rules_dir.

    Args:
        rules_dir: Directory containing ``*.yml`` Sigma Rule files.

    Returns:
        List of parsed SigmaRule objects, sorted by filename for determinism.

    Raises:
        RuleEngineError: If a YAML file is missing a required field.
    """
    rules: list[SigmaRule] = []
    for path in sorted(rules_dir.glob("*.yml")):
        with path.open() as fh:
            data: dict[str, Any] = yaml.safe_load(fh)
        rules.append(_build_rule(data, source=f"Sigma rule file '{path.name}'"))
    return rules
