import pytest
import os
from fastapi.testclient import TestClient
from unittest.mock import patch

# Set test token before importing app
os.environ["READYOPS_TOKEN"] = "test-token-123"
os.environ["USE_MOCK_DATA"] = "true"
os.environ["K8S_MCP_URL"]   = "http://mock-mcp-server/sse"


from main import app

client = TestClient(app)

# Auth headers used in every protected request
AUTH = {"X-ReadyOps-Token": "test-token-123"}


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    assert "service" in response.json()
    assert "version" in response.json()


def test_scan_returns_202():
    with patch("main.run_scan_background"):
        response = client.post("/scan",
            json={"cluster_name": "test-cluster", "triggered_by": "pytest"},
            headers=AUTH
        )
    assert response.status_code == 202
    assert "scan_id" in response.json()
    assert response.json()["job_status"] == "running"


def test_scan_id_format():
    with patch("main.run_scan_background"):
        response = client.post("/scan",
            json={"cluster_name": "test-cluster", "triggered_by": "pytest"},
            headers=AUTH
        )
    scan_id = response.json()["scan_id"]
    assert scan_id.startswith("SCAN-")


def test_scan_requires_auth():
    """Scan without token should return 401."""
    response = client.post("/scan",
        json={"cluster_name": "test-cluster", "triggered_by": "pytest"}
    )
    assert response.status_code == 401


def test_scan_invalid_cluster_name_rejected():
    with patch("main.run_scan_background"):
        response = client.post("/scan",
            json={"cluster_name": "a" * 200, "triggered_by": "pytest"},
            headers=AUTH
        )
    assert response.status_code == 422


def test_get_unknown_scan_returns_404():
    response = client.get("/scans/SCAN-DOESNOTEXIST")
    assert response.status_code == 404


def test_list_scans_returns_list():
    response = client.get("/scans")
    assert response.status_code == 200
    assert "scans" in response.json()
    assert isinstance(response.json()["scans"], list)


def test_wrong_token_returns_401():
    response = client.post("/scan",
        json={"cluster_name": "test-cluster", "triggered_by": "pytest"},
        headers={"X-ReadyOps-Token": "wrong-token"}
    )
    assert response.status_code == 401