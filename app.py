import io
import os

from flask import Flask, jsonify, request
from PIL import ExifTags, Image

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10MB

audit_records = []

PROJECT_NAME = "aerox-sentry"

raw_sha = os.environ.get("RENDER_GIT_COMMIT") or os.environ.get("GIT_SHA") or "local"
COMMIT_SHA = raw_sha[:7]


def _make_json_safe(val):
    """Recursively converts EXIF values to JSON-serializable types."""
    if isinstance(val, (str, int, float, bool)) or val is None:
        return val
    elif isinstance(val, bytes):
        try:
            return val.decode("utf-8", errors="replace")
        except Exception:
            return str(val)
    elif isinstance(val, (list, tuple)):
        return [_make_json_safe(v) for v in val]
    elif isinstance(val, dict):
        return {str(k): _make_json_safe(v) for k, v in val.items()}
    else:
        try:
            return float(val)
        except Exception:
            return str(val)


def analyze_and_scrub(file_stream, filename):
    """
    Inspects EXIF metadata for GPS and device/timestamp information,
    classifies the threat level, scrubs the image, records an audit log,
    and returns the audit record dict.
    """
    if isinstance(file_stream, (bytes, bytearray)):
        stream = io.BytesIO(file_stream)
    elif isinstance(file_stream, str):
        with open(file_stream, "rb") as f:
            stream = io.BytesIO(f.read())
    else:
        stream = file_stream

    if hasattr(stream, "seek"):
        try:
            stream.seek(0)
        except Exception:
            pass

    gps_metadata = {}
    device_metadata = {}
    all_exif = {}

    try:
        img = Image.open(stream)
        exif = img.getexif()

        if exif:
            # Check GPS IFD
            try:
                gps_ifd = exif.get_ifd(ExifTags.IFD.GPSInfo)
                for tag_id, val in gps_ifd.items():
                    tag_name = ExifTags.GPSTAGS.get(tag_id, str(tag_id))
                    gps_metadata[tag_name] = _make_json_safe(val)
            except Exception:
                pass

            # Check standard EXIF IFD
            try:
                exif_ifd = exif.get_ifd(ExifTags.IFD.Exif)
                for tag_id, val in exif_ifd.items():
                    tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                    all_exif[tag_name] = _make_json_safe(val)
            except Exception:
                pass

            for tag_id, val in exif.items():
                tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                if tag_id == 34853 or tag_name == "GPSInfo":
                    if isinstance(val, dict):
                        for g_id, g_val in val.items():
                            g_name = ExifTags.GPSTAGS.get(g_id, str(g_id))
                            gps_metadata[g_name] = _make_json_safe(g_val)
                else:
                    all_exif[tag_name] = _make_json_safe(val)

        # Also inspect _getexif if available (e.g. for JPEGs with nested tags)
        if hasattr(img, "_getexif"):
            try:
                raw_exif = img._getexif()
                if raw_exif:
                    for tag_id, val in raw_exif.items():
                        tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                        if tag_name == "GPSInfo" or tag_id == 34853:
                            if isinstance(val, dict):
                                for g_id, g_val in val.items():
                                    g_name = ExifTags.GPSTAGS.get(g_id, str(g_id))
                                    gps_metadata[g_name] = _make_json_safe(g_val)
                        else:
                            if tag_name not in all_exif:
                                all_exif[tag_name] = _make_json_safe(val)
            except Exception:
                pass

        # Perform scrubbing (strip EXIF metadata)
        clean_stream = io.BytesIO()
        img_format = img.format if img.format else "JPEG"
        if img.mode in ("RGBA", "LA") and img_format.upper() in ("JPEG", "JPG"):
            clean_img = img.convert("RGB")
        else:
            clean_img = img.copy()
        clean_img.save(clean_stream, format=img_format)
        clean_stream.seek(0)

    except Exception as e:
        record = {
            "filename": filename,
            "threat_level": "Safe (No EXIF)",
            "has_gps": False,
            "has_device_metadata": False,
            "gps_metadata": {},
            "device_metadata": {},
            "all_metadata": {},
            "scrubbed": False,
            "error": str(e),
        }
        audit_records.append(record)
        return record

    has_gps = bool(gps_metadata)
    device_metadata = dict(all_exif)
    has_device_metadata = bool(device_metadata)

    # Determine threat level
    if has_gps:
        threat_level = "High: Geolocation Exposed"
    elif has_device_metadata:
        threat_level = "Medium: Device/Timestamp Exposed"
    else:
        threat_level = "Safe (No EXIF)"

    record = {
        "filename": filename,
        "threat_level": threat_level,
        "has_gps": has_gps,
        "has_device_metadata": has_device_metadata,
        "gps_metadata": gps_metadata,
        "device_metadata": device_metadata,
        "all_metadata": all_exif,
        "scrubbed": True,
    }
    audit_records.append(record)
    return record


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": PROJECT_NAME, "commit": COMMIT_SHA})


@app.route("/api/audits", methods=["GET"])
def get_audits():
    return jsonify(audit_records)


@app.route("/api/scrub", methods=["POST"])
def scrub_image():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files["file"]
    if not file.filename:
        return jsonify({"error": "Empty filename"}), 400
    record = analyze_and_scrub(file.stream, file.filename)
    return jsonify(record), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
