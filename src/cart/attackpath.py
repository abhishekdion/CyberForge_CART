"""Evidence-backed attack-path builder (spec section 5.9, bonus B-2).

Builds graph paths ONLY from validated Relationships stored in SQLite.
Distinguishes:
- discovered adjacency (same network is NOT enough)
- demonstrated reachability (a permitted test result)
- demonstrated weakness (a verified finding)

Every edge must point at the evidence that justifies it. The builder
never invents edges to make a path look complete.
"""

from __future__ import annotations

import math
import sqlite3
from dataclasses import dataclass

_CONFIDENCE_MAP: dict[str, float] = {
    "high": 0.9,
    "medium": 0.7,
    "low": 0.5,
}


@dataclass(frozen=True)
class PathEdge:
    """An evidence-backed edge in an attack path."""
    source_id: str
    target_id: str
    relationship_type: str
    evidence_id: str
    confidence: float
    confidence_label: str


@dataclass
class AttackPath:
    """A scored, ordered sequence of attack edges."""
    edges: list[PathEdge]
    score: float

    @property
    def start_node(self) -> str:
        return self.edges[0].source_id if self.edges else ""

    @property
    def end_node(self) -> str:
        return self.edges[-1].target_id if self.edges else ""

    @property
    def hop_count(self) -> int:
        return len(self.edges)


class AttackPathBuilder:
    """Builds graph paths ONLY from validated Relationships in SQLite."""

    def __init__(self, conn: sqlite3.Connection, run_id: str):
        self.conn = conn
        self.run_id = run_id

    def load_edges(self) -> list[PathEdge]:
        """Fetch all relationships that reference valid, existing evidence."""
        query = """
            SELECT r.source_id, r.target_id, r.relationship_type, r.evidence_id, r.confidence
            FROM relationships r
            JOIN evidence e ON r.evidence_id = e.evidence_id
        """
        rows = self.conn.execute(query).fetchall()
        edges: list[PathEdge] = []
        for src, dst, rel_type, evid_id, conf_str in rows:
            weight = _CONFIDENCE_MAP.get(conf_str.lower(), 0.5)
            edges.append(
                PathEdge(
                    source_id=src,
                    target_id=dst,
                    relationship_type=rel_type,
                    evidence_id=evid_id,
                    confidence=weight,
                    confidence_label=conf_str,
                )
            )
        return edges

    def build_adjacency(
        self, edges: list[PathEdge], min_confidence: float = 0.0
    ) -> dict[str, list[PathEdge]]:
        """Group outgoing edges by source node."""
        adj: dict[str, list[PathEdge]] = {}
        for edge in edges:
            if edge.confidence >= min_confidence:
                adj.setdefault(edge.source_id, []).append(edge)
        return adj

    def find_paths_between(
        self,
        start: str,
        target: str,
        edges: list[PathEdge] | None = None,
        min_confidence: float = 0.0,
        max_depth: int = 6,
    ) -> list[AttackPath]:
        """Find all simple paths from start to target using DFS with backtracking."""
        if edges is None:
            edges = self.load_edges()

        adj = self.build_adjacency(edges, min_confidence)
        paths: list[list[PathEdge]] = []
        current_path: list[PathEdge] = []
        visited_nodes: set[str] = {start}

        def dfs(node: str, depth: int) -> None:
            if node == target:
                if current_path:
                    paths.append(list(current_path))
                return
            if depth >= max_depth:
                return
            for edge in adj.get(node, []):
                if edge.target_id in visited_nodes:
                    continue
                current_path.append(edge)
                visited_nodes.add(edge.target_id)
                dfs(edge.target_id, depth + 1)
                visited_nodes.discard(edge.target_id)
                current_path.pop()

        dfs(start, 0)

        attack_paths: list[AttackPath] = []
        for p in paths:
            score = math.prod((e.confidence for e in p), start=1.0)
            attack_paths.append(AttackPath(edges=p, score=score))

        # Rank by score descending, then shorter hops
        attack_paths.sort(key=lambda ap: (-ap.score, ap.hop_count))
        return attack_paths

    def build(
        self,
        entry_points: list[str] | None = None,
        high_value_targets: list[str] | None = None,
        max_depth: int = 6,
    ) -> list[AttackPath]:
        """Build all evidence-grounded attack paths across the entire run.

        If entry_points or high_value_targets are omitted, infers them from
        the graph topology (sources with in-degree 0 as entries, sinks or
        assets with confirmed critical/high findings as targets).
        """
        edges = self.load_edges()
        if not edges:
            return []

        all_nodes = {e.source_id for e in edges} | {e.target_id for e in edges}
        in_degrees: dict[str, int] = {n: 0 for n in all_nodes}
        out_degrees: dict[str, int] = {n: 0 for n in all_nodes}
        for e in edges:
            out_degrees[e.source_id] += 1
            in_degrees[e.target_id] += 1

        if not entry_points:
            # Nodes with in-degree 0 or tagged as entry
            entry_points = [n for n, deg in in_degrees.items() if deg == 0]
            if not entry_points and all_nodes:
                # If cycle/symmetrical, use all nodes with outgoing edges
                entry_points = [n for n, deg in out_degrees.items() if deg > 0]

        if not high_value_targets:
            # Nodes with confirmed findings or sinks (out-degree 0)
            confirmed_assets = {
                r[0]
                for r in self.conn.execute(
                    "SELECT asset_id FROM findings WHERE status = 'confirmed'"
                ).fetchall()
            }
            targets = confirmed_assets.union(
                n for n, deg in out_degrees.items() if deg == 0
            )
            high_value_targets = [t for t in targets if t in all_nodes]
            if not high_value_targets and all_nodes:
                high_value_targets = list(all_nodes)

        all_paths: list[AttackPath] = []
        for start in entry_points:
            for tgt in high_value_targets:
                if start == tgt:
                    continue
                paths = self.find_paths_between(
                    start, tgt, edges=edges, max_depth=max_depth
                )
                all_paths.extend(paths)

        # Deduplicate and sort globally
        unique_paths: dict[tuple, AttackPath] = {}
        for ap in all_paths:
            key = tuple((e.source_id, e.relationship_type, e.target_id) for e in ap.edges)
            if key not in unique_paths or ap.score > unique_paths[key].score:
                unique_paths[key] = ap

        ranked = list(unique_paths.values())
        ranked.sort(key=lambda ap: (-ap.score, ap.hop_count))
        return ranked

    def format_paths_report(self, paths: list[AttackPath]) -> str:
        """Render formatted attack path summary."""
        if not paths:
            return "No evidence-backed attack paths identified."

        # Fetch asset canonical keys / names for pretty display
        asset_map: dict[str, str] = {}
        for r in self.conn.execute("SELECT asset_id, canonical_key FROM assets").fetchall():
            asset_map[r[0]] = r[1]

        def name(nid: str) -> str:
            return asset_map.get(nid, nid)

        lines: list[str] = [f"Identified {len(paths)} attack path(s):", ""]
        for i, path in enumerate(paths, start=1):
            lines.append(f"Path {i} — Score: {path.score * 100:.1f}% ({path.hop_count} hops)")
            segs: list[str] = [name(path.edges[0].source_id)]
            for e in path.edges:
                segs.append(f"-[{e.relationship_type} ({e.confidence_label})]->")
                segs.append(name(e.target_id))
            lines.append("  " + " ".join(segs))
            lines.append(f"  Evidence: {', '.join(e.evidence_id for e in path.edges)}")
            lines.append("")
        return "\n".join(lines).strip()
