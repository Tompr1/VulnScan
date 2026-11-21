"""
Attack graph sink — publishes saved findings to the Neo4j attack graph.
"""
from __future__ import annotations

import logging
from typing import Protocol

from app.scan_jobs.processing import ProcessedFinding

logger = logging.getLogger(__name__)


class FindingGraph(Protocol):
    def record(self, workspace_id: int, target: str, finding: ProcessedFinding) -> None: ...

    def close(self) -> None: ...


class NullFindingGraph:
    """Used when the graph database is unavailable."""

    def record(self, workspace_id: int, target: str, finding: ProcessedFinding) -> None:
        return None

    def close(self) -> None:
        return None


class Neo4jFindingGraph:
    def __init__(self, client) -> None:  # app.graph.neo4j_client.Neo4jClient
        self._client = client

    def record(self, workspace_id: int, target: str, finding: ProcessedFinding) -> None:
        self._client.upsert_finding(
            workspace_id=workspace_id,
            target=target,
            plugin_id=finding.plugin_id,
            cve=finding.cve,
            risk_score=finding.risk_score,
            fingerprint=finding.fingerprint,
            title=finding.title,
            severity=finding.severity.value,
            compliance_ids=finding.compliance or None,
        )

    def close(self) -> None:
        self._client.close()


def open_finding_graph() -> FindingGraph:
    from app.graph.neo4j_client import Neo4jClient

    try:
        return Neo4jFindingGraph(Neo4jClient())
    except Exception as exc:  # the graph is optional: scans work without it
        logger.warning("Neo4j unavailable: %s", exc)
        return NullFindingGraph()
