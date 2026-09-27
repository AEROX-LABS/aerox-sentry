import io
import os
import sys

import PIL.Image
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import app, audit_records  # noqa: E402


@pytest.fixture
def client():
    app.config["TESTING"] = True
    audit_records.clear()
    with app.test_client() as test_client:
        yield test_client


def create_synthetic_image(fmt="JPEG"):
    img = PIL.Image.new("RGB", (64, 64), color="blue")
    buf = io.BytesIO()
    img.save(buf, format=fmt)
    buf.seek(0)
    return buf


def test_health_route(client):
    res = client.get("/health")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "ok"
    assert data["service"] == "aerox-sentry"
    assert "commit" in data


def test_scrub_image_success(client):
    buf = create_synthetic_image(fmt="JPEG")
    res = client.post(
        "/scrub",
        data={"photo": (buf, "vacation_shot.jpg")},
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert res.status_code == 200
    assert b"vacation_shot.jpg" in res.data
    audits_res = client.get("/api/audits")
    assert len(audits_res.get_json()) == 1


def test_invalid_extension_rejected(client):
    buf = io.BytesIO(b"echo 'malicious'")
    res = client.post(
        "/scrub",
        data={"photo": (buf, "payload.sh")},
        content_type="multipart/form-data",
    )
    assert res.status_code == 400
    data = res.get_json()
    assert "Invalid format" in data.get("error", "")


def test_summary_metrics(client):
    res = client.get("/api/audits/summary")
    assert res.status_code == 200
    data = res.get_json()
    assert "threat_distribution" in data
    assert data["total_inspected"] == 0
