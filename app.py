import os
from flask import Flask, render_template, request, jsonify, redirect, url_for
from PIL import Image, ExifTags

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10 MB upload ceiling
PROJECT_NAME = "aerox-sentry"

audit_records = []
COMMIT_SHA = os.getenv("RENDER_GIT_COMMIT", os.getenv("GIT_SHA", "local"))[:7]


def analyze_and_scrub(file_stream, filename):
    image = Image.open(file_stream)
    exif_data = image.getexif()

    exposed_tags = {}
    if exif_data:
        for tag_id, value in exif_data.items():
            tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
            exposed_tags[tag_name] = str(value)[:50]

    threat_level = "Safe (No EXIF)"
    if any(k in exposed_tags for k in ["GPSInfo", "GPSLatitude", "GPSLongitude"]):
        threat_level = "High: Geolocation Exposed"
    elif len(exposed_tags) > 0:
        threat_level = "Medium: Device/Timestamp Exposed"

    record = {
        "id": len(audit_records) + 1,
        "filename": filename,
        "tags_detected": len(exposed_tags),
        "threat_level": threat_level,
        "sample_tags": list(exposed_tags.keys())[:4]
    }
    audit_records.append(record)
    return record


@app.route("/", methods=["GET"])
def home():
    high_threat_count = sum(1 for r in audit_records if "High" in r["threat_level"])
    return render_template(
        "index.html",
        records=audit_records,
        total_scrubbed=len(audit_records),
        high_threats=high_threat_count,
        commit=COMMIT_SHA
    )


@app.route("/scrub", methods=["POST"])
def scrub_image():
    if "photo" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["photo"]
    if file.filename == "":
        return jsonify({"error": "Filename is empty"}), 400

    valid_extensions = {".jpg", ".jpeg", ".png", ".tiff"}
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in valid_extensions:
        return jsonify({"error": f"Invalid format '{ext}'. Must be an image."}), 400

    try:
        analyze_and_scrub(file.stream, file.filename)
        return redirect(url_for("home"))
    except Exception as err:
        return jsonify({"error": f"Processing failure: {str(err)}"}), 500


@app.route("/api/audits", methods=["GET"])
def api_audits():
    return jsonify(audit_records)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": PROJECT_NAME, "commit": COMMIT_SHA})


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

@app.route("/api/audits/summary", methods=["GET"])
def api_audits_summary():
    total = len(audit_records)
    high_threats = sum(1 for r in audit_records if "High" in r["threat_level"])
    medium_threats = sum(1 for r in audit_records if "Medium" in r["threat_level"])
    safe = sum(1 for r in audit_records if "Safe" in r["threat_level"])
    return jsonify({
        "total_inspected": total,
        "threat_distribution": {
            "high": high_threats,
            "medium": medium_threats,
            "safe": safe
        },
        "safe_ratio": round((safe / total * 100), 2) if total > 0 else 100.0
    })
