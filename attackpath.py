"""Attack Path Analyzer (multi-stage) — standard library only, Python 3.11+.

Models an attack graph of hosts and lateral-movement opportunities,
enumerates all simple paths between two nodes under confidence/depth
constraints, ranks them by multiplicative risk score, and renders a
plain-text report.

Pipeline (one function group per part):
    Part 1  Data modelling      Node / Edge / AttackGraph dataclasses
    Part 2  Path enumeration    find_attack_paths   (DFS + backtracking)
    Part 3  Risk scoring        score_path, rank_paths
    Part 4  Report formatting   format_report
    Part 5  Self-validation     __main__ integration test

Run directly:  python attackpath.py
"""

from __future__ import annotations

import math
import sys
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# PART 1 — Data modelling
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Node:
    """A network host in the attack graph.

    Design choices:
      * ``id`` is a stable machine key (edges and lookups use it); ``label``
        is the human-readable name used only in reports. Keeping them
        separate means renaming a host never breaks graph references.
      * ``frozen=True`` makes nodes immutable reference data, so traversal
        code can never mutate shared state mid-search.
      * ``open_ports`` / ``tags`` default to empty lists (callers may omit
        optional metadata) and are treated as read-only after construction.
    """

    id: str
    label: str
    os: str
    open_ports: list[int] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Edge:
    """A lateral-movement opportunity from ``src`` to ``dst``.

    Design choices:
      * Endpoints reference ``Node.id`` (stable keys), not labels, so edges
        stay valid if display names change.
      * ``confidence`` is a probability-like weight in [0, 1]; it is
        validated at construction so bad data fails fast instead of silently
        skewing scores later.
    """

    src: str
    dst: str
    technique: str
    confidence: float

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                f"confidence must be in [0, 1], got {self.confidence!r} "
                f"for edge {self.src}->{self.dst}"
            )


@dataclass(frozen=True)
class AttackGraph:
    """Directed graph of hosts (nodes) and movement opportunities (edges)."""

    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)

    def node_ids(self) -> frozenset[str]:
        """Set of all node IDs in the graph."""
        return frozenset(node.id for node in self.nodes)

    def adjacency(self, min_confidence: float = 0.0) -> dict[str, list[Edge]]:
        """Out-neighbor map ``{node_id: [edges]}`` filtered by confidence.

        Built once per search so the DFS does O(1) neighbor lookups instead
        of scanning every edge at each step. Also validates that all edge
        endpoints exist in the node set (fail fast on malformed graphs).
        """
        ids = self.node_ids()
        adj: dict[str, list[Edge]] = {}
        for edge in self.edges:
            if edge.src not in ids or edge.dst not in ids:
                raise ValueError(
                    f"edge {edge.src}->{edge.dst} references an unknown node"
                )
            if edge.confidence >= min_confidence:
                adj.setdefault(edge.src, []).append(edge)
        return adj


# ---------------------------------------------------------------------------
# PART 2 — Path enumeration (DFS + backtracking)
# ---------------------------------------------------------------------------


def find_attack_paths(
    graph: AttackGraph,
    start: str,
    target: str,
    min_confidence: float = 0.5,
    max_depth: int = 6,
) -> list[list[Edge]]:
    """Find all simple paths from ``start`` to ``target``.

    A path is *simple* (no node appears twice), uses only edges with
    confidence >= min_confidence, and has at most ``max_depth`` hops (edges).
    Results are sorted by total score (product of edge confidences)
    descending; on equal scores shorter paths come first.

    Time complexity: let V = #nodes, E = #edges passing the confidence filter,
    D = max_depth, P = number of qualifying simple paths. The DFS visits each
    distinct path prefix once, so cost is O(P * D + V + E). P is bounded by
    roughly k^D for average degree k (each hop offers <= k choices), so the
    worst case is exponential in D — inherent to returning *all* simple paths
    (counting them is #P-hard; any algorithm must at least write them out).
    Space: O(D + V) working state (recursion stack, on-path set) plus
    O(P * D) to store the results.

    Raises ValueError on unknown start/target or invalid parameters.
    """
    if not 0.0 <= min_confidence <= 1.0:
        raise ValueError(
            f"min_confidence must be in [0, 1], got {min_confidence!r}"
        )
    if max_depth < 1:
        raise ValueError(f"max_depth must be >= 1, got {max_depth}")
    if start == target:
        raise ValueError("start and target must be different nodes")

    ids = graph.node_ids()
    if start not in ids:
        raise ValueError(f"unknown start node {start!r}")
    if target not in ids:
        raise ValueError(f"unknown target node {target!r}")

    adjacency = graph.adjacency(min_confidence)

    paths: list[list[Edge]] = []
    current_path: list[Edge] = []
    on_path: set[str] = {start}  # nodes currently in the path (simple-path guard)

    def dfs(node: str, depth: int) -> None:
        if node == target:
            paths.append(list(current_path))  # copy: backtracking mutates it
            return  # a simple path ends at its first arrival at the target
        if depth >= max_depth:
            return  # hop budget exhausted before reaching the target
        for edge in adjacency.get(node, ()):
            if edge.dst in on_path:
                continue  # would repeat a node -> not simple
            current_path.append(edge)
            on_path.add(edge.dst)
            dfs(edge.dst, depth + 1)
            on_path.discard(edge.dst)  # backtrack
            current_path.pop()         # backtrack

    dfs(start, 0)

    # score_path (Part 3) is module-level; resolved at call time.
    paths.sort(key=lambda p: (-score_path(p), len(p)))
    return paths


# ---------------------------------------------------------------------------
# PART 3 — Risk scoring
# ---------------------------------------------------------------------------


def score_path(path: list[Edge]) -> float:
    """Multiplicative risk score of a path, in [0, 1].

    Score = product of all edge confidences. The product models the joint
    probability that every hop succeeds: each weak link drags the whole
    chain down multiplicatively (one broken step kills the path). An empty
    path scores 1.0 — the multiplicative identity ("no movement needed"
    carries no confidence penalty).
    """
    return math.prod((edge.confidence for edge in path), start=1.0)


def rank_paths(paths: list[list[Edge]]) -> list[tuple[float, list[Edge]]]:
    """Rank paths by (score descending, length ascending).

    Returns ``(score, path)`` tuples sorted so the highest-scoring path is
    first; on exactly equal scores the shorter path ranks higher — fewer hops
    means fewer independent failure points and less exposure time.

    Note: tie-breaking compares exact float equality. Mathematically equal
    products computed from different edge sets can differ by an ulp; such
    near-ties are indistinguishable in practice, so exact comparison is used.
    """
    scored = [(score_path(path), path) for path in paths]
    scored.sort(key=lambda item: (-item[0], len(item[1])))
    return scored


# ---------------------------------------------------------------------------
# PART 4 — Output formatter
# ---------------------------------------------------------------------------


def format_report(
    ranked_paths: list[tuple[float, list[Edge]]], nodes: list[Node]
) -> str:
    """Render ranked paths as a plain-text report.

    Paths are shown with human-readable node labels (looked up from ``nodes``);
    unknown IDs fall back to the raw ID so a malformed graph never crashes the
    reporter. Scores are printed as percentages with one decimal place, e.g.
    ``Score: 72.3%``.
    """
    label_by_id = {node.id: node.label for node in nodes}

    def label(node_id: str) -> str:
        return label_by_id.get(node_id, node_id)

    lines: list[str] = ["=== Attack Path Report ==="]

    if not ranked_paths:
        lines.append("No attack paths found.")
        return "\n".join(lines)

    lines.append(f"Paths found: {len(ranked_paths)}")
    for rank, (score, path) in enumerate(ranked_paths, start=1):
        lines.append("")
        if not path:  # defensive: zero-hop path has no edges to render
            lines.append(f"Path {rank} — Score: {score * 100:.1f}% (0 hops)")
            continue

        # Node sequence = first edge's src, then each edge's dst.
        rendered: list[str] = []
        previous = path[0].src
        for edge in path:
            rendered.append(label(previous))
            rendered.append(f"[{edge.technique}]")
            previous = edge.dst
        rendered.append(label(previous))

        lines.append(
            f"Path {rank} — Score: {score * 100:.1f}% ({len(path)} hops)"
        )
        lines.append("    " + " → ".join(rendered))

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# PART 5 — Integration test (self-validation)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # The report uses U+2192 (→). Force UTF-8 output so it renders on
    # Windows consoles whose default code page is cp1252.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    # --- Sample lab topology: 6 nodes, 9 edges ----------------------------
    graph = AttackGraph(
        nodes=[
            Node("attacker", "Attacker Box", "Kali Linux 2026.1", [80, 443], ["entry-point"]),
            Node("web-01", "Web Server (web-01)", "Ubuntu 24.04 LTS", [22, 80, 443], ["internet-facing"]),
            Node("app-01", "App Server (app-01)", "Debian 12", [22, 5432, 8080], ["internal"]),
            Node("file-01", "File Server (file-01)", "Windows Server 2022", [135, 445, 3390], ["smb-share"]),
            Node("db-01", "Database (db-01)", "RHEL 9", [22, 5432], ["internal"]),
            Node("domain_controller", "Domain Controller (dc-01)", "Windows Server 2022", [88, 135, 389, 445, 636], ["domain-controller"]),
        ],
        edges=[
            Edge("attacker", "web-01", "SSH_BRUTEFORCE", 0.9),
            Edge("attacker", "file-01", "SMB_RELAY", 0.6),
            Edge("web-01", "app-01", "SQL_INJECTION", 0.8),
            Edge("web-01", "db-01", "SSH_BRUTEFORCE", 0.5),
            Edge("web-01", "file-01", "PASS_THE_HASH", 0.75),
            Edge("app-01", "domain_controller", "PASS_THE_HASH", 0.85),
            Edge("app-01", "db-01", "SQL_INJECTION", 0.7),
            Edge("file-01", "domain_controller", "SMB_RELAY", 0.9),
            # Deliberately below the default min_confidence of 0.5: any path
            # through this edge must be filtered out by find_attack_paths.
            Edge("db-01", "domain_controller", "SSH_BRUTEFORCE", 0.4),
        ],
    )

    START = "attacker"
    TARGET = "domain_controller"
    MIN_CONFIDENCE = 0.5
    MAX_DEPTH = 6

    # Self-validation of the sample data itself (Part 5 requirements).
    assert len(graph.nodes) >= 6, "sample graph must have at least 6 nodes"
    assert len(graph.edges) >= 8, "sample graph must have at least 8 edges"

    paths = find_attack_paths(graph, START, TARGET, MIN_CONFIDENCE, MAX_DEPTH)
    ranked = rank_paths(paths)
    print(format_report(ranked, graph.nodes))

    # Required assertions: at least one path found; top score <= 1.0.
    assert ranked, "expected at least one attack path from attacker to domain_controller"
    assert ranked[0][0] <= 1.0, f"top-ranked score {ranked[0][0]} exceeds 1.0"

    # Extra sanity: ranking must be non-increasing and every kept edge must
    # respect the confidence floor used for the search.
    for (score_a, _), (score_b, _) in zip(ranked, ranked[1:]):
        assert score_a >= score_b, "ranked paths are not sorted by descending score"
    for _, path in ranked:
        assert all(edge.confidence >= MIN_CONFIDENCE for edge in path)

    print(f"\nSelf-validation passed: {len(ranked)} path(s), top score {ranked[0][0]:.4f}")


# ---------------------------------------------------------------------------
# BONUS — Scaling analysis
# ---------------------------------------------------------------------------
# Q: If the graph had 1000 nodes and average degree 10, what would be the
#    worst-case complexity of find_attack_paths, and how would you optimize
#    it for large graphs without changing the return contract?
#
# A: With V = 1000 and average out-degree k ~ 10, the DFS explores at most
#    O(k^D) path prefixes (every simple path is a prefix of some walk), so
#    worst-case time is O(D * k^D + V + E). For the default D = 6 that is
#    ~6 * 10^6 node visits — fine. But the bound is exponential in D: at
#    D = 20 it is ~10^20, and the output itself (P paths of length D) can be
#    exponentially large, so any algorithm that returns ALL simple paths pays
#    Omega(P * D) just to emit them. Enumerating all simple paths is #P-hard
#    in general; no polynomial-time fix exists for arbitrary graphs.
#
# Optimizations that keep the return contract (all simple paths, sorted):
#   1. Reachability pruning: forward BFS from start + backward BFS from
#      target, then drop every node not present in both sets before DFS. On
#      sparse real-world attack graphs this often cuts V by an order of
#      magnitude and removes dead-end branches the DFS would otherwise
#      explore fully.
#   2. Meet-in-the-middle (bidirectional) enumeration: grow paths from start
#      to depth D//2 and from target backwards to depth D - D//2, then join
#      compatible halves at shared junction nodes (with disjointness checks so
#      no node repeats). This reduces the exponential base from k^D to
#      ~k^(D/2), turning e.g. 10^12 work into ~10^6 for D = 12, k = 10.
#   3. Constant-factor wins: integer node indices instead of string IDs
#      (faster hashing/comparison), precomputed adjacency arrays, and an
#      on-path bitset instead of a set[str] when V fits in machine words.
#   4. If the contract could ever be relaxed to "top-K paths", add score-
#      bounded branch-and-bound: since every remaining hop multiplies by at
#      most 1, a partial path whose current product already falls below the
#      K-th best complete score found so far can be pruned safely. That is
#      the single biggest win in practice — but it changes completeness, so
#      it is not used here.
