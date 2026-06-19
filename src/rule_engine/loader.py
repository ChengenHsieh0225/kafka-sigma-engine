"""Sigma Rule loader for the Kafka Sigma Engine."""

from pathlib import Path
from typing import Any

import yaml

from src.exceptions import RuleEngineError
from src.models import SigmaRule


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

        try:
            rule = SigmaRule(
                id=data["id"],
                title=data["title"],
                level=data["level"],
                detection=data["detection"],
            )
        except KeyError as exc:
            raise RuleEngineError(
                f"Sigma rule file '{path.name}' is missing required field: {exc}"
            ) from exc

        rules.append(rule)

    return rules
