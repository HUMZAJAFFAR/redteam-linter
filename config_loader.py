"""YAML-backed sink rule loader for RedTeam Linter.

``analyzer.py`` ships with a seed table of dangerous callables so the tool works
out of the box, but production deployments must be able to extend, reweight or
replace that table without patching Python source.  This module owns that
boundary: it reads ``sinks.yaml`` and returns a validated list of sink rules.

The contract is deliberately forgiving — a missing, unreadable or malformed
configuration file degrades to :data:`DEFAULT_SINKS` instead of aborting the
scan.  A linter that crashes on bad input is worse than a linter with a smaller
rule set.

Rule schema (every key except ``name`` is optional)::

    - name: "os.system"            # required: fully qualified callable
      category: "RCE"              # default: "UNKNOWN"
      requires_shell_true: true    # default: false

Typical usage::

    from config_loader import load_sink_config

    sinks = load_sink_config("sinks.yaml")
"""

from __future__ import annotations

import logging
from copy import deepcopy
from typing import Any, Dict, List, Optional

LOGGER = logging.getLogger(__name__)

try:  # PyYAML is a declared dependency, but never let its absence kill a scan.
    import yaml
except ImportError:  # pragma: no cover - exercised only in broken installs
    yaml = None  # type: ignore[assignment]

#: Fallback rule set mirroring the seed table in ``analyzer.py``.
#:
#: ``requires_shell_true`` records whether the sink *needs* ``shell=True`` to be
#: exploitable; the analyzer can use it today or a future taint pass can use it
#: to prioritise candidates.
DEFAULT_SINKS: List[Dict[str, Any]] = [
    {"name": "eval", "category": "RCE", "requires_shell_true": False},
    {"name": "exec", "category": "RCE", "requires_shell_true": False},
    {"name": "compile", "category": "RCE", "requires_shell_true": False},
    {"name": "os.system", "category": "RCE", "requires_shell_true": True},
    {"name": "os.popen", "category": "RCE", "requires_shell_true": True},
    {"name": "subprocess.call", "category": "RCE", "requires_shell_true": True},
    {"name": "pickle.loads", "category": "DESERIALIZATION", "requires_shell_true": False},
]

#: Top-level YAML keys that may wrap the rule list.
_WRAPPER_KEYS = ("sinks", "rules", "sink_rules")

_DEFAULT_CATEGORY = "UNKNOWN"


def _default_sinks() -> List[Dict[str, Any]]:
    """Return a fresh copy of the fallback rules.

    Callers routinely mutate the returned list (filtering, annotating), so a
    shared module-level object would leak state between scans.
    """
    return deepcopy(DEFAULT_SINKS)


def _normalize_rule(raw: Any) -> Optional[Dict[str, Any]]:
    """Validate and normalize one YAML entry.

    Returns ``None`` for entries that cannot possibly match a call site (no
    usable ``name``), which keeps a single typo from poisoning the rule set.
    """
    if not isinstance(raw, dict):
        LOGGER.warning("Ignoring sink rule %r: expected a mapping.", raw)
        return None

    name = raw.get("name")
    if not isinstance(name, str) or not name.strip():
        LOGGER.warning("Ignoring sink rule %r: missing 'name'.", raw)
        return None

    category = raw.get("category", _DEFAULT_CATEGORY)
    if not isinstance(category, str) or not category.strip():
        category = _DEFAULT_CATEGORY

    requires_shell_true = raw.get("requires_shell_true", False)
    if not isinstance(requires_shell_true, bool):
        LOGGER.warning(
            "Sink %r has non-boolean 'requires_shell_true' (%r); coercing to bool.",
            name,
            requires_shell_true,
        )
        requires_shell_true = bool(requires_shell_true)

    rule: Dict[str, Any] = {
        "name": name.strip(),
        "category": category.strip().upper(),
        "requires_shell_true": requires_shell_true,
    }

    # Preserve operator-supplied metadata (severity, remediation, CWE...) so
    # downstream reporting can use it without a schema change here.
    for key, value in raw.items():
        if key not in rule:
            rule[key] = value

    return rule


def _extract_rules(document: Any) -> Optional[List[Any]]:
    """Find the rule list inside a parsed YAML document."""
    if isinstance(document, list):
        return document
    if isinstance(document, dict):
        for key in _WRAPPER_KEYS:
            if key in document and isinstance(document[key], list):
                return document[key]
    return None


def load_sink_config(yaml_path: str) -> List[Dict[str, Any]]:
    """Load sink rules from ``yaml_path``, falling back to defaults on error.

    Parameters
    ----------
    yaml_path:
        Path to the YAML rule file (normally ``sinks.yaml``).

    Returns
    -------
    List[Dict[str, Any]]
        Normalized rules with the keys ``name``, ``category`` and
        ``requires_shell_true``.  Never empty: any failure returns
        :data:`DEFAULT_SINKS` instead of raising.
    """
    if yaml is None:
        LOGGER.error("PyYAML is not installed; using built-in sink rules.")
        return _default_sinks()

    try:
        with open(yaml_path, "r", encoding="utf-8") as handle:
            document = yaml.safe_load(handle)
    except FileNotFoundError:
        LOGGER.warning("Sink config %s not found; using built-in sink rules.", yaml_path)
        return _default_sinks()
    except OSError as exc:
        LOGGER.error("Cannot read sink config %s (%s); using built-in rules.", yaml_path, exc)
        return _default_sinks()
    except yaml.YAMLError as exc:
        LOGGER.error("Malformed YAML in %s (%s); using built-in rules.", yaml_path, exc)
        return _default_sinks()

    if document is None:
        LOGGER.warning("Sink config %s is empty; using built-in sink rules.", yaml_path)
        return _default_sinks()

    raw_rules = _extract_rules(document)
    if raw_rules is None:
        LOGGER.error(
            "Sink config %s must be a list or contain a 'sinks:' list; "
            "using built-in rules.",
            yaml_path,
        )
        return _default_sinks()

    rules = [rule for rule in (_normalize_rule(item) for item in raw_rules) if rule]
    if not rules:
        LOGGER.error("No valid sink rules in %s; using built-in rules.", yaml_path)
        return _default_sinks()

    LOGGER.debug("Loaded %d sink rules from %s", len(rules), yaml_path)
    return rules


__all__ = ["load_sink_config", "DEFAULT_SINKS"]
