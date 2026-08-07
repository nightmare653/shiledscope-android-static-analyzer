"""
ShieldScope — web UI.

Upload an APK or IPA; it statically detects root/jailbreak detection and SSL
pinning (which mechanisms, how many independent layers), then serves the
matching step-by-step bypass guides + resources.

Run:  python app.py     ->  http://127.0.0.1:5000
"""

import os
import tempfile
import traceback

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from werkzeug.utils import secure_filename

from analyzer import analyze_file

BASE = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

MAX_MB = 600  # apk/ipa can be large

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_MB * 1024 * 1024
CORS(app)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    if "file" not in request.files:
        return jsonify({"ok": False, "error": "No file uploaded (field name must be 'file')."}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"ok": False, "error": "Empty filename."}), 400

    safe = secure_filename(f.filename)
    fd, tmp_path = tempfile.mkstemp(prefix="ss_", suffix="_" + safe, dir=UPLOAD_DIR)
    os.close(fd)
    try:
        f.save(tmp_path)
        result = analyze_file(tmp_path, original_name=safe)
        status = 200 if result.get("ok") else 422
        return jsonify(result), status
    except Exception as e:
        traceback.print_exc()
        return jsonify({"ok": False, "error": f"Analysis failed: {e}"}), 500
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass


@app.route("/api/health")
def health():
    return jsonify({"ok": True, "service": "shieldscope"})


if __name__ == "__main__":
    print("ShieldScope running at http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
