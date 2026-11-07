import pytest
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)

def test_health_endpoint():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "platform" in data

def test_sample_contracts_endpoint():
    response = client.get("/api/v1/contracts/samples")
    assert response.status_code == 200
    samples = response.json()
    assert len(samples) >= 5
    assert any(s["id"] == "reentrancy" for s in samples)

def test_scan_contract_api():
    sample_code = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SimpleBank {
    mapping(address => uint256) public balances;
    function withdraw() external {
        uint256 bal = balances[msg.sender];
        (bool s, ) = msg.sender.call{value: bal}("");
        balances[msg.sender] = 0;
    }
}
"""
    response = client.post("/api/v1/scan", json={"source_code": sample_code, "filename": "SimpleBank.sol"})
    assert response.status_code == 200
    data = response.json()
    assert data["target_name"] == "SimpleBank.sol"
    assert data["summary"]["total_findings"] >= 1
    assert data["summary"]["security_score"] < 100

def test_scan_validation_error():
    # Invalid or non-solidity code
    response = client.post("/api/v1/scan", json={"source_code": "console.log('hello world');", "filename": "app.js"})
    assert response.status_code == 400

def test_lab_scenarios_endpoint():
    response = client.get("/api/v1/lab/scenarios")
    assert response.status_code == 200
    scenarios = response.json()
    assert len(scenarios) >= 4

def test_lab_run_endpoint():
    response = client.post("/api/v1/lab/run", json={"lab_id": "reentrancy", "target_type": "vulnerable"})
    assert response.status_code == 200
    data = response.json()
    assert data["passed"] is True
    assert len(data["parsed_trace"]) > 0

def test_pdf_report_download():
    # First create a scan
    scan_res = client.post(
        "/api/v1/scan",
        json={
            "source_code": "pragma solidity ^0.8.20; contract Test { address public owner; function setOwner(address o) public { owner = o; } }",
            "filename": "Test.sol"
        }
    )
    assert scan_res.status_code == 200
    scan_id = scan_res.json()["scan_id"]

    # Request PDF
    pdf_res = client.get(f"/api/v1/reports/{scan_id}/pdf")
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"
    assert len(pdf_res.content) > 1000

    # Request JSON
    json_res = client.get(f"/api/v1/reports/{scan_id}/json")
    assert json_res.status_code == 200
    assert "report_metadata" in json_res.json()
