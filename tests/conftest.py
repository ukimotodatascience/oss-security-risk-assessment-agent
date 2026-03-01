import pytest
import tempfile
import json
from pathlib import Path
import respx
from httpx import Response

@pytest.fixture
def mock_external_apis():
    """Mock OSV, EPSS, and GitHub APIs"""
    with respx.mock(base_url="https://api.osv.dev/v1/query") as osv_mock:
        osv_mock.post("").respond(
            status_code=200,
            json={
                "vulns": [
                    {
                        "id": "CVE-2021-1234",
                        "summary": "Fake vulnerability for testing",
                        "severity": [
                            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
                        ]
                    }
                ]
            }
        )
        
        with respx.mock(base_url="https://api.first.org/epss") as epss_mock:
            epss_mock.get(path__startswith="/").respond(
                status_code=200,
                json={
                    "data": [
                        {"epss": "0.15", "percentile": "0.90"}
                    ]
                }
            )
            
            with respx.mock(base_url="https://api.github.com/") as gh_mock:
                gh_mock.get(path__startswith="/repos/").respond(
                    status_code=200,
                    json={
                        "pushed_at": "2020-01-01T00:00:00Z"
                    }
                )
                
                with respx.mock(base_url="https://api.securityscorecards.dev/") as sc_mock:
                    sc_mock.get(path__startswith="/projects/").respond(
                        status_code=200,
                        json={
                            "score": 4.5,
                            "checks": []
                        }
                    )
                    
                    yield {
                        "osv": osv_mock,
                        "epss": epss_mock,
                        "github": gh_mock,
                        "scorecard": sc_mock
                    }

@pytest.fixture
def dummy_repo():
    """Create a temporary directory structure mimicking a repository"""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_path = Path(tmpdir)
        
        # Create necessary directories
        (repo_path / ".github" / "workflows").mkdir(parents=True)
        (repo_path / "src").mkdir()
        
        yield repo_path
