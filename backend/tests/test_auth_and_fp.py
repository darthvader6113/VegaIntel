"""
Tests for Authentication, False Positive Prevention Engine, and On-Demand IOC Submission.
"""
from fastapi.testclient import TestClient
import pytest
from app.main import app
from app.core.false_positive import inspect_for_false_positive


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_false_positive_prevention_engine():
    # 1. Benign Apex Domain should be flagged as False Positive
    is_fp, reason, code = inspect_for_false_positive("domain", "google.com")
    assert is_fp is True
    assert "apex" in reason.lower()

    # 2. Benign CDN Apex Domain
    is_fp, reason, _ = inspect_for_false_positive("domain", "cloudflare.com")
    assert is_fp is True

    # 3. RFC1918 Private IP
    is_fp, reason, code = inspect_for_false_positive("ip", "10.0.0.1")
    assert is_fp is True
    assert code == "rfc1918_private"

    # 4. Known Public DNS Anycast
    is_fp, reason, code = inspect_for_false_positive("ip", "8.8.8.8")
    assert is_fp is True
    assert "resolver" in reason.lower()

    # 5. Empty zero-byte file MD5
    is_fp, reason, code = inspect_for_false_positive("md5", "d41d8cd98f00b204e9800998ecf8427e")
    assert is_fp is True
    assert code == "empty_file_hash"

    # 6. Real Malicious IP / Domain should pass
    is_fp, reason, code = inspect_for_false_positive("ip", "185.220.101.5")
    assert is_fp is False
    assert code == "valid"

    is_fp, reason, code = inspect_for_false_positive("domain", "oast.live")
    assert is_fp is False
    assert code == "valid"


def test_user_registration_and_login(client):
    email = "analyst_test_2026@vegaintel.io"
    password = "SecOpsPassword!2026"

    # 1. Register new user
    reg_resp = client.post("/api/auth/register", json={
        "email": email,
        "password": password,
        "full_name": "Test SecOps Analyst",
        "organization": "Cyber Defense Unit"
    })
    assert reg_resp.status_code == 200
    data = reg_resp.json()
    assert "access_token" in data
    assert data["user"]["email"] == email

    # 2. Login with correct credentials
    login_resp = client.post("/api/auth/login", json={
        "email": email,
        "password": password
    })
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]
    assert token

    # 3. Test /api/auth/me with Bearer token
    me_resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_resp.status_code == 200
    assert me_resp.json()["email"] == email

    # 4. Login with incorrect password
    bad_login = client.post("/api/auth/login", json={
        "email": email,
        "password": "wrongpassword123"
    })
    assert bad_login.status_code == 401


def test_request_and_ingest_ioc_with_fp_check(client):
    # 1. Requesting a false positive should be rejected
    rejected_resp = client.post("/api/iocs/request", json={
        "ioc": "google.com",
        "notes": "Testing benign apex"
    })
    assert rejected_resp.status_code == 400
    assert "False Positive Prevented" in rejected_resp.json()["detail"]

    # 2. Requesting a valid malicious indicator should succeed
    valid_resp = client.post("/api/iocs/request", json={
        "ioc": "194.38.20.41",
        "notes": "Lazarus C2 beacon candidate",
        "target_cve": "CVE-2021-44228",
        "tags": ["reconnaissance", "manual-lead"]
    })
    assert valid_resp.status_code == 200
    res_data = valid_resp.json()
    assert res_data["status"] == "success"
    assert "ip:194.38.20.41" in res_data["fingerprint"]


def test_today_new_iocs(client):
    resp = client.get("/api/iocs/today")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_new_today" in data
    assert "items" in data

