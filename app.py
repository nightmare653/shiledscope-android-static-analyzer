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


# ---------------------------------------------------------------------------
#  OPTIONAL AI layer (additive; off unless configured). Never touches analysis.
# ---------------------------------------------------------------------------
@app.route("/api/ai/status")
def ai_status():
    try:
        from ai import load_config, probe
        cfg = load_config()
        out = {"config": cfg.to_dict(redact=True)}
        out.update(probe(cfg))
        return jsonify(out)
    except Exception as e:
        return jsonify({"ok": False, "enabled": False, "detail": "AI unavailable: %s" % e})


@app.route("/api/ai/config", methods=["POST"])
def ai_config():
    try:
        from ai import save_config, probe
        cfg = save_config(request.get_json(force=True) or {})
        out = {"ok": True, "config": cfg.to_dict(redact=True)}
        out.update({"probe": probe(cfg)})
        return jsonify(out)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/ai/finding", methods=["POST"])
def ai_finding():
    try:
        from ai.analyst import analyze_finding
        body = request.get_json(force=True) or {}
        return jsonify(analyze_finding(body.get("finding") or {}, body.get("meta")))
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/ai/plan", methods=["POST"])
def ai_plan():
    try:
        from ai.analyst import pentest_plan
        body = request.get_json(force=True) or {}
        return jsonify(pentest_plan(body.get("result") or body))
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/ai/chat", methods=["POST"])
def ai_chat():
    try:
        from ai.chatbot import ask
        body = request.get_json(force=True) or {}
        return jsonify(ask(body.get("messages") or [], result=body.get("result")))
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ---- dynamic: Frida device bridge + AI bypass agent (needs a device) ----
@app.route("/api/ai/frida/devices")
def ai_frida_devices():
    try:
        from ai import frida_runner
        return jsonify(frida_runner.list_devices())
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/ai/frida/run", methods=["POST"])
def ai_frida_run():
    try:
        from ai import frida_runner
        b = request.get_json(force=True) or {}
        return jsonify(frida_runner.run_script(
            b.get("package"), b.get("script") or "", device_id=b.get("device_id"),
            collect_seconds=int(b.get("seconds", 6))))
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/ai/frida/bypass", methods=["POST"])
def ai_frida_bypass():
    try:
        from ai.frida_agent import bypass
        b = request.get_json(force=True) or {}
        return jsonify(bypass(b.get("result") or {}, b.get("package"),
                              goal=b.get("goal", "ssl"), device_id=b.get("device_id"),
                              max_iters=int(b.get("max_iters", 4))))
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


if __name__ == "__main__":
    print("ShieldScope running at http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
