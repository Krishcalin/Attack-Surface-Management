"""
EASM Scanner -- Asset Relationship Graph
In-memory graph model for asset relationships and attack path analysis.
No external dependencies (no Neo4j) -- uses adjacency-list representation.
Provides traversal, attribution path, and relationship queries.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class GraphNode:
    """A node in the asset graph."""
    node_id: str               # e.g., "domain:example.com"
    asset_type: str            # domain, ip, port, asn, cert, url, cidr
    value: str                 # e.g., "example.com"
    attributes: dict[str, Any] = field(default_factory=dict)

    def __hash__(self) -> int:
        return hash(self.node_id)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, GraphNode):
            return NotImplemented
        return self.node_id == other.node_id


@dataclass
class GraphEdge:
    """An edge in the asset graph."""
    source: str               # node_id
    target: str               # node_id
    relation: str             # e.g., "resolves_to", "has_cert", "in_asn"
    weight: float = 1.0
    attributes: dict[str, Any] = field(default_factory=dict)


# Relationship types
RELATIONS = {
    "resolves_to":     "Domain resolves to IP (A/AAAA record)",
    "cname_to":        "Domain is CNAME to another domain",
    "has_cert":        "Host presents this certificate",
    "cert_lists_san":  "Certificate lists this domain as SAN",
    "in_asn":          "IP belongs to this ASN",
    "in_cidr":         "IP is within this CIDR",
    "has_port":        "IP has this open port",
    "serves_url":      "Host serves this URL",
    "registered_by":   "Domain registered by this registrant",
    "uses_nameserver": "Domain uses this name server",
    "shares_ns_with":  "Domains share name servers",
    "shares_ip_with":  "Domains share an IP address",
    "has_mx":          "Domain has this MX record",
    "owned_by":        "ASN/entity owned by organization",
    "child_of":        "Subdomain of parent domain",
}


class AssetGraph:
    """In-memory asset relationship graph."""

    def __init__(self) -> None:
        self.nodes: dict[str, GraphNode] = {}
        self.edges: list[GraphEdge] = []
        self._adj: dict[str, list[GraphEdge]] = defaultdict(list)
        self._rev: dict[str, list[GraphEdge]] = defaultdict(list)

    # ── Node operations ─────────────────────────────────────

    def add_node(
        self,
        asset_type: str,
        value: str,
        attributes: Optional[dict] = None,
    ) -> GraphNode:
        """Add or update a node."""
        node_id = f"{asset_type}:{value}"
        if node_id in self.nodes:
            node = self.nodes[node_id]
            if attributes:
                node.attributes.update(attributes)
            return node

        node = GraphNode(
            node_id=node_id,
            asset_type=asset_type,
            value=value,
            attributes=attributes or {},
        )
        self.nodes[node_id] = node
        return node

    def get_node(self, asset_type: str, value: str) -> Optional[GraphNode]:
        return self.nodes.get(f"{asset_type}:{value}")

    # ── Edge operations ─────────────────────────────────────

    def add_edge(
        self,
        source_type: str,
        source_value: str,
        target_type: str,
        target_value: str,
        relation: str,
        weight: float = 1.0,
        attributes: Optional[dict] = None,
    ) -> GraphEdge:
        """Add an edge between two nodes (creates nodes if needed)."""
        self.add_node(source_type, source_value)
        self.add_node(target_type, target_value)

        src_id = f"{source_type}:{source_value}"
        tgt_id = f"{target_type}:{target_value}"

        # Dedupe
        for e in self._adj[src_id]:
            if e.target == tgt_id and e.relation == relation:
                return e

        edge = GraphEdge(
            source=src_id,
            target=tgt_id,
            relation=relation,
            weight=weight,
            attributes=attributes or {},
        )
        self.edges.append(edge)
        self._adj[src_id].append(edge)
        self._rev[tgt_id].append(edge)
        return edge

    # ── Queries ─────────────────────────────────────────────

    def neighbors(
        self,
        asset_type: str,
        value: str,
        relation: Optional[str] = None,
    ) -> list[GraphNode]:
        """Get all neighbors of a node (optionally filtered by relation)."""
        node_id = f"{asset_type}:{value}"
        result: list[GraphNode] = []
        for edge in self._adj.get(node_id, []):
            if relation and edge.relation != relation:
                continue
            node = self.nodes.get(edge.target)
            if node:
                result.append(node)
        return result

    def reverse_neighbors(
        self,
        asset_type: str,
        value: str,
        relation: Optional[str] = None,
    ) -> list[GraphNode]:
        """Get nodes that point TO this node."""
        node_id = f"{asset_type}:{value}"
        result: list[GraphNode] = []
        for edge in self._rev.get(node_id, []):
            if relation and edge.relation != relation:
                continue
            node = self.nodes.get(edge.source)
            if node:
                result.append(node)
        return result

    def find_path(
        self,
        src_type: str, src_value: str,
        tgt_type: str, tgt_value: str,
        max_depth: int = 10,
    ) -> list[str]:
        """BFS shortest path between two nodes. Returns list of node_ids."""
        src_id = f"{src_type}:{src_value}"
        tgt_id = f"{tgt_type}:{tgt_value}"

        if src_id not in self.nodes or tgt_id not in self.nodes:
            return []

        visited: set[str] = {src_id}
        queue: deque[list[str]] = deque([[src_id]])

        while queue:
            path = queue.popleft()
            if len(path) > max_depth:
                break

            current = path[-1]
            if current == tgt_id:
                return path

            for edge in self._adj.get(current, []):
                if edge.target not in visited:
                    visited.add(edge.target)
                    queue.append(path + [edge.target])
            # Also traverse reverse edges for undirected search
            for edge in self._rev.get(current, []):
                if edge.source not in visited:
                    visited.add(edge.source)
                    queue.append(path + [edge.source])

        return []

    def nodes_by_type(self, asset_type: str) -> list[GraphNode]:
        """Get all nodes of a specific type."""
        return [
            n for n in self.nodes.values()
            if n.asset_type == asset_type
        ]

    def shared_infrastructure(
        self, domain1: str, domain2: str,
    ) -> dict[str, list[str]]:
        """Find shared infrastructure between two domains."""
        shared: dict[str, list[str]] = {
            "shared_ips": [],
            "shared_nameservers": [],
            "shared_certs": [],
            "shared_asns": [],
        }

        d1_ips = {n.value for n in self.neighbors("domain", domain1, "resolves_to")}
        d2_ips = {n.value for n in self.neighbors("domain", domain2, "resolves_to")}
        shared["shared_ips"] = sorted(d1_ips & d2_ips)

        d1_ns = {n.value for n in self.neighbors("domain", domain1, "uses_nameserver")}
        d2_ns = {n.value for n in self.neighbors("domain", domain2, "uses_nameserver")}
        shared["shared_nameservers"] = sorted(d1_ns & d2_ns)

        return shared

    # ── Build graph from store ──────────────────────────────

    def build_from_assets(self, assets: list, dns_records: Optional[dict] = None) -> None:
        """Populate graph from a list of Asset objects."""
        for asset in assets:
            atype = asset.asset_type if isinstance(asset.asset_type, str) else asset.asset_type
            self.add_node(atype, asset.value, asset.attributes)

            if asset.parent:
                # Determine relation based on types
                if atype == "ip":
                    self.add_edge(
                        "domain", asset.parent, "ip", asset.value,
                        "resolves_to",
                    )
                elif atype == "port":
                    self.add_edge(
                        "ip", asset.parent, "port",
                        f"{asset.parent}:{asset.value}",
                        "has_port",
                    )
                elif atype == "cidr":
                    self.add_edge(
                        "asn", asset.parent, "cidr", asset.value,
                        "in_asn",
                    )
                elif atype == "domain" and asset.parent:
                    self.add_edge(
                        "domain", asset.parent, "domain", asset.value,
                        "child_of",
                    )

    def add_dns_edges(self, dns_records: dict) -> None:
        """Add DNS resolution edges from resolver results."""
        for hostname, records in dns_records.items():
            for rec in records:
                if rec.record_type in ("A", "AAAA"):
                    self.add_edge(
                        "domain", hostname, "ip", rec.value,
                        "resolves_to",
                    )
                elif rec.record_type == "CNAME":
                    self.add_edge(
                        "domain", hostname, "domain", rec.value,
                        "cname_to",
                    )
                elif rec.record_type == "MX":
                    self.add_edge(
                        "domain", hostname, "domain", rec.value,
                        "has_mx",
                    )
                elif rec.record_type == "NS":
                    self.add_edge(
                        "domain", hostname, "domain", rec.value,
                        "uses_nameserver",
                    )

    def add_tls_edges(self, host: str, tls_info: Any) -> None:
        """Add certificate edges from TLS analysis."""
        cert_id = getattr(tls_info, "serial", "") or host
        self.add_node("cert", cert_id, {
            "subject_cn": getattr(tls_info, "subject_cn", ""),
            "issuer_org": getattr(tls_info, "issuer_org", ""),
            "not_after": getattr(tls_info, "not_after", ""),
        })
        self.add_edge("domain", host, "cert", cert_id, "has_cert")

        for san in getattr(tls_info, "sans", []) or []:
            self.add_edge("cert", cert_id, "domain", san, "cert_lists_san")

    def add_whois_edges(self, domain: str, whois_record: Any) -> None:
        """Add WHOIS registration edges."""
        org = getattr(whois_record, "registrant_org", "") or ""
        if org:
            self.add_edge(
                "domain", domain, "org", org,
                "registered_by",
            )
        for ns in getattr(whois_record, "name_servers", []) or []:
            self.add_edge(
                "domain", domain, "domain", ns,
                "uses_nameserver",
            )

    # ── Stats ───────────────────────────────────────────────

    def stats(self) -> dict[str, Any]:
        """Return graph statistics."""
        type_counts: dict[str, int] = defaultdict(int)
        for n in self.nodes.values():
            type_counts[n.asset_type] += 1

        rel_counts: dict[str, int] = defaultdict(int)
        for e in self.edges:
            rel_counts[e.relation] += 1

        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "nodes_by_type": dict(type_counts),
            "edges_by_relation": dict(rel_counts),
        }

    def to_dict(self) -> dict[str, Any]:
        """Export graph as serializable dict."""
        return {
            "nodes": [
                {
                    "id": n.node_id,
                    "type": n.asset_type,
                    "value": n.value,
                    "attributes": n.attributes,
                }
                for n in self.nodes.values()
            ],
            "edges": [
                {
                    "source": e.source,
                    "target": e.target,
                    "relation": e.relation,
                    "weight": e.weight,
                }
                for e in self.edges
            ],
        }
