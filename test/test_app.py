import io
import pytest
from PIL import Image
from app import app, audit_records


@pytest.fixture
def client():
    app.config["TESTING"] = True
    audit_records.clear()
    with app.test_client() as client:
        yield client


def create_synthetic_image(fmt="JPEG"):
    buf = io.BytesIO()
    img = Image.new("RGB", (64, 64), color="blue")
    img.save(buf, format=fmt)
    buf.seek(0)
    return buf


def test_health_route(client):
    res = client.get("/health")
    assert res.status_code == 200
    assert res.get_json()["status"] == "ok"
    assert res.get_json()["service"] == "aerox-sentry"
    assert "commit" in res.get_json()


def test_scrub_image_success(client):
    img_data = create_synthetic_image("JPEG")
    res = client.post(
        "/scrub",
        data={"photo": (img_data, "vacation_shot.jpg")},
        content_type="multipart/form-data",
        follow_redirects=True
    )
    assert res.status_code == 200
    assert b"vacation_shot.jpg" in res.data
    assert len(client.get("/api/audits").get_json()) == 1


def test_invalid_extension_rejected(client):
    invalid_file = io.BytesIO(b"MALICIOUS_PAYLOAD_STRING")
    res = client.post(
        "/scrub",
        data={"photo": (invalid_file, "payload.sh")},
        content_type="multipart/form-data"
    )
    assert res.status_code == 400
    assert "Invalid format" in res.get_json()["error"]
