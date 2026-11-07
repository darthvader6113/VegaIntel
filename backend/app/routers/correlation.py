"""
Threat Correlation Graph API Router.
Produces graph topology (nodes and edges) for visual analyst inspection.
"""
from typing import Optional
from fastapi import APIRouter, Depends, Query
from app.database import get_db

router = APIRouter(prefix="/api/correlation", tags=["Correlation Graph"])


@router.get("/graph")
def get_correlation_graph(
    focus_cve: Optional[str] = Query(None),
    focus_ioc: Optional[str] = Query(None),
    limit: int = 100,
    db=Depends(get_db)
):
    nodes = []
    edges = []
    seen_nodes = set()

    def add_node(node_id: str, label: str, node_type: str, details: dict):
        if node_id not in seen_nodes:
            seen_nodes.add(node_id)
            nodes.append({
                "id": node_id,
                "label": label,
                "type": node_type,
                "data": details
            })

    # Fetch relationships
    rel_query = {}
    if focus_cve:
        rel_query["$or"] = [{"source_id": focus_cve}, {"target_id": focus_cve}]
    elif focus_ioc:
        rel_query["$or"] = [{"source_id": focus_ioc}, {"target_id": focus_ioc}]

    relationships = list(db.relationships.find(rel_query, {"_id": 0}).limit(limit))

    for rel in relationships:
        s_id = rel.get("source_id")
        t_id = rel.get("target_id")
        if not s_id or not t_id:
            continue
        s_type = rel.get("source_type", "entity")
        t_type = rel.get("target_type", "entity")
        r_type = rel.get("relationship_type") or rel.get("relation_type") or "related_to"

        # Register source node
        add_node(s_id, s_id, s_type, {"type": s_type})
        # Register target node
        add_node(t_id, t_id, t_type, {"type": t_type})

        # Register edge
        edges.append({
            "id": rel.get("relationship_id") or f"{s_id}->{t_id}",
            "source": s_id,
            "target": t_id,
            "label": r_type,
            "confidence": rel.get("confidence", 70)
        })

    # Enrich node details if available
    for n in nodes:
        ntype = n["type"]
        nid = n["id"]
        if ntype == "cve":
            doc = db.cves.find_one({"cve_id": nid}, {"_id": 0, "cvss_score": 1, "severity": 1, "description": 1})
            if doc:
                n["data"].update(doc)
                n["label"] = f"{nid} ({doc.get('severity')})"
        elif ntype == "ioc":
            doc = db.iocs.find_one({"fingerprint": nid}, {"_id": 0, "ioc_type": 1, "ioc_value": 1, "sighting_count": 1, "sources": 1})
            if doc:
                n["data"].update(doc)
                n["label"] = f"{doc.get('ioc_value')} [{doc.get('sighting_count')}x]"
        elif ntype == "apt_group":
            doc = db.apt_groups.find_one({"group_id": nid}, {"_id": 0, "name": 1, "origin_country": 1})
            if doc:
                n["data"].update(doc)
                n["label"] = f"APT: {doc.get('name')}"
        elif ntype == "malware":
            doc = db.malware.find_one({"malware_id": nid}, {"_id": 0, "name": 1, "malware_type": 1})
            if doc:
                n["data"].update(doc)
                n["label"] = f"Malware: {doc.get('name')}"

    return {
        "nodes": nodes,
        "edges": edges,
        "summary": {
            "total_nodes": len(nodes),
            "total_edges": len(edges)
        }
    }

