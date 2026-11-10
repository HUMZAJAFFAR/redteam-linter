"""Reporting and redaction engine for RedTeam Linter.

This module is the *only* place where findings are rendered for a human or
written to disk.  It is therefore the enforcement point for the tool's OpSec
policy:

    Raw secrets and raw matched source lines must never reach the terminal or
    any serialized artifact.  Redaction is strictly **output-side**: the
    harvester/analyzer keep the original bytes in memory so that future taint
    analysis can still reason about them, and every field is scrubbed here
    immediately before it is displayed or persisted.

Design notes
------------
*   :class:`ReportGenerator` accepts findings as plain ``dict`` objects (the
    analyzer's native format), dataclass instances, or any object exposing
    ``to_dict()`` / ``__dict__``.  A small set of key aliases is understood so
    that the reporter does not force a rename in ``analyzer.py``.
*   ``arguments_passed`` is deliberately *not* redacted: it is the bridge for
    future taint tracing and carries structural data, not raw credential
    material.  Keep that field clean and JSON-serializable in the analyzer.
*   Terminal output uses :mod:`rich`; JSON output is dependency-free stdlib.

Typical usage::

    from reporter import ReportGenerator

    generator = ReportGenerator(findings, files_scanned=len(targets))
    generator.print_report()
    generator.export_to_json("redteam-report.json")
"""

from __future__ import annotations

import json
import logging
from collections import Counter
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Union

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

LOGGER = logging.getLogger(__name__)

#: Canonical severity ladder, most severe first.  Anything unknown is treated
#: as informational so a malformed analyzer rule can never crash the reporter.
SEVERITY_ORDER: Dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}

#: Rich styles for the severity column.
SEVERITY_STYLES: Dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim",
    "UNKNOWN": "dim",
}

#: Fields that may contain raw secret material.  These are scrubbed at any
#: nesting depth inside a finding, both for the terminal and for JSON.
SENSITIVE_FIELDS: frozenset = frozenset({"matched_snippet", "secret_value"})

#: Marker appended to truncated secrets.
REDACTED_MARKER = "***REDACTED***"

#: Strings longer than this are considered potential secrets and truncated.
REDACT_LENGTH_THRESHOLD = 10

#: Maximum number of characters of redacted evidence shown in the terminal.
_EVIDENCE_WIDTH = 46

#: Alias table: canonical key -> accepted alternatives produced by the
#: harvester/analyzer.  First match wins.
_FIELD_ALIASES: Dict[str, Sequence[str]] = {
    "file_path": ("file_path", "filepath", "file", "path", "filename", "target"),
    "line_number": ("line_number", "line", "lineno", "line_no"),
    "severity": ("severity", "level", "risk"),
    "category": ("category", "vuln_category", "class", "type"),
    "sink": ("sink", "sink_name", "name", "rule_id", "rule"),
    "matched_snippet": ("matched_snippet", "snippet", "line_content", "context", "evidence"),
    "secret_value": ("secret_value", "secret", "match", "matched_value"),
    "arguments_passed": ("arguments_passed", "args", "arguments"),
    "description": ("description", "message", "detail"),
}


class ReportGenerator:
    """Render, summarize and export linter findings without leaking secrets.

    Parameters
    ----------
    findings:
        Sequence of finding mappings/objects, or a full report mapping of the
        shape ``{"findings": [...], "total_files_scanned": N}``.
    files_scanned:
        Optional authoritative count of files inspected.  When omitted, the
        reporter falls back to the number of distinct files present in the
        findings, which is a lower bound.
    console:
        Optional pre-configured :class:`rich.console.Console`.  Injecting one
        keeps tests quiet and lets ``main.py`` share a single console.
    """

    def __init__(
        self,
        findings: Union[Sequence[Any], Mapping[str, Any]],
        files_scanned: Optional[int] = None,
        console: Optional[Console] = None,
    ) -> None:
        self._console: Console = console or Console()
        raw_findings, reported_file_count = self._unwrap(findings)

        # Normalize once so both renderers see identical, canonical shapes.
        self._findings: List[Dict[str, Any]] = [self._normalize(f) for f in raw_findings]

        if files_scanned is not None:
            self._files_scanned = max(0, int(files_scanned))
        elif reported_file_count is not None:
            self._files_scanned = max(0, int(reported_file_count))
        else:
            self._files_scanned = len(
                {f["file_path"] for f in self._findings if f.get("file_path")}
            )

    # ------------------------------------------------------------------
    # Construction helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _unwrap(
        findings: Union[Sequence[Any], Mapping[str, Any]]
    ) -> "tuple[List[Any], Optional[int]]":
        """Accept either a bare sequence of findings or a wrapped report.

        Returns the finding sequence plus an optional ``total_files_scanned``
        value discovered in the wrapper.
        """
        if isinstance(findings, Mapping):
            inner = findings.get("findings", [])
            count = findings.get("total_files_scanned")
            return list(inner or []), (int(count) if isinstance(count, int) else None)
        if findings is None:
            return [], None
        return list(findings), None

    @staticmethod
    def _as_mapping(finding: Any) -> Dict[str, Any]:
        """Coerce a finding (dict, dataclass or plain object) into a dict."""
        if isinstance(finding, Mapping):
            return dict(finding)
        to_dict = getattr(finding, "to_dict", None)
        if callable(to_dict):
            result = to_dict()
            if isinstance(result, Mapping):
                return dict(result)
        if hasattr(finding, "__dict__"):
            return dict(vars(finding))
        raise TypeError(
            f"Unsupported finding type {type(finding)!r}: expected a mapping, "
            "a dataclass, or an object with to_dict()."
        )

    @classmethod
    def _normalize(cls, finding: Any) -> Dict[str, Any]:
        """Map an arbitrary finding onto the canonical schema.

        Unknown keys are preserved verbatim (minus sensitive ones, which are
        handled during redaction) so downstream consumers never lose context.
        """
        source = cls._as_mapping(finding)
        canonical: Dict[str, Any] = {}

        for key, aliases in _FIELD_ALIASES.items():
            canonical[key] = cls._first(source, aliases, default="")

        severity = str(canonical.get("severity") or "").strip().upper() or "UNKNOWN"
        canonical["severity"] = severity if severity in SEVERITY_ORDER else "UNKNOWN"

        line = canonical.get("line_number")
        try:
            canonical["line_number"] = int(line) if line not in (None, "") else 0
        except (TypeError, ValueError):
            canonical["line_number"] = 0

        args = canonical.get("arguments_passed")
        canonical["arguments_passed"] = args if args is not None else []

        # Preserve anything the analyzer emits that we do not know about.
        consumed = set(_FIELD_ALIASES) | {
            alias for aliases in _FIELD_ALIASES.values() for alias in aliases
        }
        for key, value in source.items():
            if key not in consumed:
                canonical[key] = value

        return canonical

    @staticmethod
    def _first(source: Mapping[str, Any], keys: Sequence[str], default: Any = "") -> Any:
        """Return the first present, non-empty value among ``keys``."""
        for key in keys:
            if key in source and source[key] not in (None, ""):
                return source[key]
        return default

    # ------------------------------------------------------------------
    # Redaction
    # ------------------------------------------------------------------
    def _redact_secret(self, value: str) -> str:
        """Truncate anything that looks like a credential.

        A value longer than :data:`REDACT_LENGTH_THRESHOLD` characters is
        reduced to its first four characters plus :data:`REDACTED_MARKER`, so
        an operator can still correlate a finding with a file without ever
        seeing the usable secret.  Short values (booleans, flags, empty
        strings) pass through untouched.
        """
        if value is None:
            return ""
        text = value if isinstance(value, str) else str(value)
        if len(text) > REDACT_LENGTH_THRESHOLD:
            return f"{text[:4]}{REDACTED_MARKER}"
        return text

    def _redact_payload(self, payload: Any) -> Any:
        """Recursively scrub every sensitive field inside a structure."""
        if isinstance(payload, Mapping):
            clean: Dict[str, Any] = {}
            for key, value in payload.items():
                if key in SENSITIVE_FIELDS and isinstance(value, (str, int, float, bool)):
                    clean[key] = self._redact_secret(value)
                elif key in SENSITIVE_FIELDS and value is not None:
                    # Lists/objects in a sensitive slot: stringify then scrub.
                    clean[key] = self._redact_secret(str(value))
                else:
                    clean[key] = self._redact_payload(value)
            return clean
        if isinstance(payload, (list, tuple)):
            return [self._redact_payload(item) for item in payload]
        return payload

    # ------------------------------------------------------------------
    # Aggregation
    # ------------------------------------------------------------------
    def _severity_counts(self) -> "Counter[str]":
        """Count findings per severity, preserving the canonical ladder."""
        counter: Counter = Counter({name: 0 for name in SEVERITY_ORDER})
        for finding in self._findings:
            counter[finding["severity"]] += 1
        # Deterministic ordering: canonical ladder first, then exotic labels.
        ordered = Counter()
        for name in SEVERITY_ORDER:
            ordered[name] = counter.get(name, 0)
        for name, count in counter.items():
            if name not in ordered:
                ordered[name] = count
        return ordered

    def _sorted_findings(self) -> List[Dict[str, Any]]:
        """Order findings by severity, then file, then line."""
        return sorted(
            self._findings,
            key=lambda f: (
                SEVERITY_ORDER.get(f["severity"], 99),
                str(f.get("file_path") or ""),
                int(f.get("line_number") or 0),
            ),
        )

    def summary(self) -> Dict[str, Any]:
        """Build the summary header written to JSON and shown in the terminal."""
        return {
            "total_files_scanned": self._files_scanned,
            "total_findings": len(self._findings),
            "severity_breakdown": dict(self._severity_counts()),
        }

    # ------------------------------------------------------------------
    # Terminal rendering
    # ------------------------------------------------------------------
    def _evidence_text(self, finding: Mapping[str, Any]) -> str:
        """Build a short, redacted evidence string for the table."""
        evidence = finding.get("matched_snippet") or finding.get("secret_value") or ""
        note = ""
        if finding.get("matched_snippet") and finding.get("secret_value"):
            note = " [secret]"
        redacted = self._redact_secret(str(evidence)).replace("\n", " ").strip()
        if len(redacted) > _EVIDENCE_WIDTH:
            redacted = redacted[: _EVIDENCE_WIDTH - 3] + "..."
        return f"{redacted}{note}" if redacted else "-"

    def print_report(self, console: Optional[Console] = None) -> None:
        """Print the color-coded findings table and a summary panel."""
        target = console or self._console
        summary = self.summary()

        if not self._findings:
            target.print(
                Panel(
                    "No findings. Target looks clean — for now.",
                    title="[bold]RedTeam Linter[/bold]",
                    border_style="green",
                )
            )
            return

        table = Table(
            title="RedTeam Linter — Findings",
            title_style="bold white",
            header_style="bold white",
            border_style="bright_black",
            expand=True,
            pad_edge=False,
        )
        table.add_column("#", justify="right", style="dim", width=4)
        table.add_column("Severity", width=10, no_wrap=True)
        table.add_column("Category", width=16, overflow="fold")
        table.add_column("Location", overflow="fold", ratio=2)
        table.add_column("Sink", overflow="fold", ratio=1)
        table.add_column("Evidence", overflow="fold", ratio=2)

        for index, finding in enumerate(self._sorted_findings(), start=1):
            severity = finding["severity"]
            location = "{file}:{line}".format(
                file=finding.get("file_path") or "<unknown>",
                line=finding.get("line_number") or "?",
            )
            table.add_row(
                str(index),
                Text(severity, style=SEVERITY_STYLES.get(severity, "dim")),
                str(finding.get("category") or "-"),
                location,
                str(finding.get("sink") or "-"),
                self._evidence_text(finding),
            )

        target.print(table)

        breakdown = "  ".join(
            f"[{SEVERITY_STYLES.get(name, 'dim')}]{name}[/]: {count}"
            for name, count in summary["severity_breakdown"].items()
        )
        target.print(
            Panel(
                f"[bold]Files scanned:[/] {summary['total_files_scanned']}    "
                f"[bold]Total findings:[/] {summary['total_findings']}\n{breakdown}",
                title="[bold]Summary[/bold]",
                border_style="bright_black",
            )
        )

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------
    def build_payload(self) -> Dict[str, Any]:
        """Return the redacted, JSON-ready report structure.

        Redaction happens on a deep copy, so the in-memory findings handed to
        future taint analysis are never mutated.
        """
        redacted: List[Dict[str, Any]] = [
            self._redact_payload(deepcopy(finding)) for finding in self._sorted_findings()
        ]
        return {"summary": self.summary(), "findings": redacted}

    def export_to_json(self, filepath: str) -> None:
        """Write the redacted report to ``filepath`` as UTF-8 JSON.

        Every ``matched_snippet`` and ``secret_value`` is passed through
        :meth:`_redact_secret` before serialization, so the artifact is safe to
        attach to a ticket or paste into a report.
        """
        destination = Path(filepath)
        if destination.parent and not destination.parent.exists():
            destination.parent.mkdir(parents=True, exist_ok=True)

        payload = self.build_payload()
        with destination.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False, sort_keys=False)
            handle.write("\n")

        LOGGER.info(
            "Wrote %d redacted findings to %s", payload["summary"]["total_findings"], destination
        )


__all__ = ["ReportGenerator", "SEVERITY_ORDER", "SEVERITY_STYLES"]
