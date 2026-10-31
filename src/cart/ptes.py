"""Canonical PTES phases (spec section 9).

Every Task, ToolEvent and Finding record must carry one of these phases.
Internal labels must stay consistent across event logs, findings and the
final report.
"""

from __future__ import annotations

from enum import StrEnum


class PtesPhase(StrEnum):
    PRE_ENGAGEMENT = "pre-engagement-interactions"
    INTELLIGENCE_GATHERING = "intelligence-gathering"
    THREAT_MODELING = "threat-modeling"
    VULNERABILITY_ANALYSIS = "vulnerability-analysis"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post-exploitation"
    REPORTING = "reporting"


# Mapping helper for the first release: engine activity -> canonical phase.
DEFAULT_ACTTIVITY_PHASE: dict[str, PtesPhase] = {
    "candidate_network_discovery": PtesPhase.PRE_ENGAGEMENT,
    "host_discovery": PtesPhase.INTELLIGENCE_GATHERING,
    "port_service_discovery": PtesPhase.INTELLIGENCE_GATHERING,
    "web_crawl_endpoint_discovery": PtesPhase.INTELLIGENCE_GATHERING,
    "binary_static_analysis": PtesPhase.INTELLIGENCE_GATHERING,
    "finding_verification": PtesPhase.VULNERABILITY_ANALYSIS,
    "attack_path_construction": PtesPhase.THREAT_MODELING,
    "report_generation": PtesPhase.REPORTING,
}
