"""
Integration tests for FastAPI endpoints with strictly live OSINT data.
Verifies all 8 intelligence modules, STIX 2.1 exporter, and health checks.
"""
from fastapi.testclient import TestClient
import pytest
from app.main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_health_check(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "HEALTHY"


def test_overview_stats(client):
    resp = client.get("/api/overview/stats")
    assert resp.status_code == 200
    data = resp.json()
    metrics = data["metrics"]
    assert "total_canonical_iocs" in metrics
    assert "total_sightings" in metrics
    assert "duplicates_prevented" in metrics
    assert "deduplication_ratio_pct" in metrics
    assert metrics["total_sightings"] >= metrics["total_canonical_iocs"]
    assert metrics["duplicates_prevented"] >= 0


def test_cve_explorer(client):
    resp = client.get("/api/cves/")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] > 0

    first_cve = data["items"][0]["cve_id"]
    detail = client.get(f"/api/cves/{first_cve}")
    assert detail.status_code == 200
    cve_data = detail.json()
    assert "cve" in cve_data
    assert cve_data["cve"]["cve_id"] == first_cve


def test_ioc_repository(client):
    resp = client.get("/api/iocs/")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] > 0

    first_ioc_fp = data["items"][0]["fingerprint"]
    detail = client.get(f"/api/iocs/detail?fingerprint={first_ioc_fp}")
    assert detail.status_code == 200
    ioc_data = detail.json()
    assert "canonical_ioc" in ioc_data
    assert ioc_data["canonical_ioc"]["fingerprint"] == first_ioc_fp
    assert len(ioc_data["sightings"]) >= 1


def test_apt_groups(client):
    resp = client.get("/api/apt/")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1


def test_malware(client):
    resp = client.get("/api/malware/")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1


def test_poc_library(client):
    resp = client.get("/api/pocs/")
    assert resp.status_code == 200
    data = resp.json()
    assert "TREAT AS REFERENCE ONLY" in data["advisory"]


def test_feed_monitoring(client):
    resp = client.get("/api/feeds/status")
    assert resp.status_code == 200
    data = resp.json()
    feed_names = [f["feed_name"] for f in data["feeds"]]
    assert len(feed_names) >= 4


def test_export_stix_21(client):
    resp = client.get("/api/export/stix")
    assert resp.status_code == 200
    bundle = resp.json()
    assert bundle["type"] == "bundle"
    assert "objects" in bundle


def test_export_csv(client):
    resp = client.get("/api/export/csv")
    assert resp.status_code == 200
    assert "Fingerprint,Type,Value" in resp.text


def test_correlation_graph(client):
    resp = client.get("/api/correlation/graph")
    assert resp.status_code == 200
    graph = resp.json()
    assert "nodes" in graph
    assert "edges" in graph
