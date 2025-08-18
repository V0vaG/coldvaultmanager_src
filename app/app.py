#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, re, json, threading
from datetime import datetime
from flask import (
    Flask, request, send_file, redirect, url_for,
    render_template, jsonify, abort, flash
)

# ======================================
# Paths, defaults, utils
# ======================================
BASE_DIR       = os.path.dirname(os.path.abspath(__file__))
DATA_DIR       = os.path.join(BASE_DIR, "data")
FIRMWARE_DIR   = os.path.join(BASE_DIR, "firmware")

EVENTS_JSON    = os.path.join(DATA_DIR, "events.json")   # list[dict]
DEVICES_JSON   = os.path.join(DATA_DIR, "devices.json")  # dict[serial] -> info
GROUPS_JSON    = os.path.join(DATA_DIR, "groups.json")   # dict[group]  -> info
SETTINGS_JSON  = os.path.join(DATA_DIR, "settings.json") # dict
EVENTS_LOG_TXT = os.path.join(DATA_DIR, "events.log")    # text log

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(FIRMWARE_DIR, exist_ok=True)

_lock = threading.Lock()

DEFAULT_SETTINGS = {
    "firmware_dir": FIRMWARE_DIR,   # can be changed in /settings
    "default_firmware": "",         # used only if default_strategy == "pinned"
    "default_strategy": "latest",   # "latest" or "pinned"
    "events_cap": 2000              # cap event list length
}

def now_iso():
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def _load_json(path, default):
    with _lock:
        if not os.path.exists(path):
            return default
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return default

def _save_json(path, data):
    with _lock:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)

def human_size(n):
    s = float(n)
    for u in ["B", "KB", "MB", "GB", "TB"]:
        if s < 1024:
            return f"{s:.1f} {u}"
        s /= 1024
    return f"{s:.1f} PB"

# --------------------------------------
# Settings / devices / groups / events
# --------------------------------------
def load_settings():
    s = _load_json(SETTINGS_JSON, DEFAULT_SETTINGS.copy())
    for k, v in DEFAULT_SETTINGS.items():
        s.setdefault(k, v)
    return s

def save_settings(s):
    _save_json(SETTINGS_JSON, s)

def load_devices():
    # { serial: { device_id, group, last_seen, last_version, last_filename } }
    return _load_json(DEVICES_JSON, {})

def save_devices(d):
    _save_json(DEVICES_JSON, d)

def load_groups():
    # { group: { firmware_file, signature, note } }
    return _load_json(GROUPS_JSON, {})

def save_groups(g):
    _save_json(GROUPS_JSON, g)

def load_events():
    return _load_json(EVENTS_JSON, [])

def save_events(evts):
    _save_json(EVENTS_JSON, evts)

def append_event(e):
    events = load_events()
    events.append(e)
    cap = int(load_settings().get("events_cap", 2000))
    if cap and len(events) > cap:
        events = events[-cap:]
    save_events(events)
    # line log
    line = f"[{e.get('ts')}] {e.get('ip','?')} serial={e.get('serial','?')} device_id={e.get('device_id','?')} file={e.get('filename','?')} ver={e.get('version','?')}"
    with _lock, open(EVENTS_LOG_TXT, "a", encoding="utf-8") as f:
        f.write(line + "\n")

# ======================================
# Firmware discovery + selection logic
# ======================================
SEMVER_RE = re.compile(
    r"^(ColdVault|ColdVolt)_(\d+)\.(\d+)\.(\d+)\.ino\.bin$", re.IGNORECASE
)

def parse_version_from_filename(filename):
    m = SEMVER_RE.match(filename)
    if not m:
        return None
    major, minor, patch = map(int, (m.group(2), m.group(3), m.group(4)))
    return (filename, (major, minor, patch))

def version_to_str(tup):
    if not tup: return ""
    return f"{tup[0]}.{tup[1]}.{tup[2]}"

def find_all_firmwares(dir_path):
    files = []
    if not os.path.isdir(dir_path):
        return files
    for n in os.listdir(dir_path):
        p = os.path.join(dir_path, n)
        if os.path.isfile(p):
            parsed = parse_version_from_filename(n)
            if parsed:
                files.append(parsed)
    return files

def find_latest_firmware(dir_path):
    cands = find_all_firmwares(dir_path)
    if not cands:
        return None
    return max(cands, key=lambda t: t[1])  # by (maj, min, patch)

def choose_firmware_for_device(serial: str, device_id: str):
    s = load_settings()
    groups = load_groups()
    devices = load_devices()

    group_name = devices.get(serial, {}).get("group", "")
    chosen = None

    # 1) If device in a group and group has a bound file -> use it
    if group_name and group_name in groups:
        file_for_group = groups[group_name].get("firmware_file", "")
        if file_for_group:
            p = os.path.join(s["firmware_dir"], file_for_group)
            if os.path.isfile(p):
                parsed = parse_version_from_filename(file_for_group)
                version = version_to_str(parsed[1]) if parsed else ""
                chosen = {"path": p, "filename": file_for_group, "version": version}

    # 2) Otherwise fall back to global strategy (pinned)
    if not chosen:
        if s.get("default_strategy") == "pinned" and s.get("default_firmware"):
            fn = s["default_firmware"]
            p = os.path.join(s["firmware_dir"], fn)
            if os.path.isfile(p):
                parsed = parse_version_from_filename(fn)
                version = version_to_str(parsed[1]) if parsed else ""
                chosen = {"path": p, "filename": fn, "version": version}

    # 3) Otherwise serve latest
    if not chosen:
        latest = find_latest_firmware(s["firmware_dir"])
        if latest:
            fn, ver = latest
            p = os.path.join(s["firmware_dir"], fn)
            chosen = {"path": p, "filename": fn, "version": version_to_str(ver)}

    return chosen

def record_device_touch(serial, device_id, filename, version):
    devices = load_devices()
    info = devices.get(serial, {})
    info["device_id"] = device_id or info.get("device_id", "")
    info["last_seen"] = now_iso()
    info["last_filename"] = filename
    info["last_version"] = version
    devices[serial] = info
    save_devices(devices)

# ======================================
# Flask app
# ======================================
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret-change-me")

# -------- Dashboard --------
@app.get("/")
def home():
    s = load_settings()
    latest = find_latest_firmware(s["firmware_dir"])
    latest_ctx = None
    if latest:
        fn, ver = latest
        latest_ctx = {"filename": fn, "version": f"{ver[0]}.{ver[1]}.{ver[2]}"}
    events = load_events()
    devices = load_devices()
    return render_template(
        "home.html",
        title="Dashboard",
        latest=latest_ctx,
        events=events,
        devices=devices,
        datetime=datetime
    )

# -------- Firmware list UI --------
@app.get("/firmware")
def firmware_list():
    s = load_settings()
    items = []
    for (fn, ver) in find_all_firmwares(s["firmware_dir"]):
        p = os.path.join(s["firmware_dir"], fn)
        st = os.stat(p)
        items.append({
            "filename": fn,
            "version": f"{ver[0]}.{ver[1]}.{ver[2]}",
            "size": st.st_size,
            "size_h": human_size(st.st_size),
            "mtime": datetime.utcfromtimestamp(st.st_mtime).isoformat() + "Z"
        })
    items.sort(key=lambda x: tuple(map(int, x["version"].split("."))), reverse=True)
    return render_template("firmware.html", title="Firmware Files", items=items, fw_dir=s["firmware_dir"], datetime=datetime)

# -------- Groups management --------
@app.route("/groups", methods=["GET", "POST"])
def groups_page():
    s = load_settings()
    groups = load_groups()
    devices = load_devices()
    fw_files = [fn for (fn, _) in find_all_firmwares(s["firmware_dir"])]

    if request.method == "POST":
        act = request.form.get("action", "")

        if act == "add_group":
            name = request.form.get("group", "").strip()
            fw   = request.form.get("firmware_file", "").strip()
            sig  = request.form.get("signature", "").strip()
            note = request.form.get("note", "").strip()
            if not name:
                flash("שם קבוצה חובה")
            else:
                groups[name] = {"firmware_file": fw, "signature": sig, "note": note}
                save_groups(groups)
                flash(f"קבוצה '{name}' נוספה")
            return redirect(url_for("groups_page"))

        if act == "assign_device":
            serial = request.form.get("serial", "").strip()
            group  = request.form.get("group", "").strip()
            if not serial or not group or group not in groups:
                flash("שגיאה בשיוך מכשיר/קבוצה")
            else:
                info = devices.get(serial, {})
                info["group"] = group
                devices[serial] = info
                save_devices(devices)
                flash(f"Serial {serial} שובץ לקבוצה {group}")
            return redirect(url_for("groups_page"))

        if act == "update_group":
            name = request.form.get("group", "").strip()
            fw   = request.form.get("firmware_file", "").strip()
            sig  = request.form.get("signature", "").strip()
            note = request.form.get("note", "").strip()
            if name in groups:
                if fw:
                    p = os.path.join(s["firmware_dir"], fw)
                    if not os.path.isfile(p):
                        flash("קובץ עדכון לא קיים בתיקייה", "error")
                        return redirect(url_for("groups_page"))
                groups[name]["firmware_file"] = fw
                groups[name]["signature"] = sig
                groups[name]["note"] = note
                save_groups(groups)
                flash(f"הקבוצה '{name}' עודכנה")
            return redirect(url_for("groups_page"))

        if act == "delete_group":
            group = request.form.get("group", "").strip()
            if group in groups:
                del groups[group]
                # detach devices
                changed = False
                for serial, info in list(devices.items()):
                    if info.get("group") == group:
                        info.pop("group", None)
                        devices[serial] = info
                        changed = True
                if changed:
                    save_devices(devices)
                save_groups(groups)
                flash(f"קבוצה '{group}' נמחקה")
            return redirect(url_for("groups_page"))

    return render_template("groups.html", title="Groups", groups=groups, fw_files=fw_files, datetime=datetime)

# -------- Events --------
@app.get("/events")
def events_page():
    events = load_events()
    return render_template("events.html", title="Events", events=events, datetime=datetime)

# -------- Settings --------
@app.route("/settings", methods=["GET", "POST"])
def settings_page():
    s = load_settings()
    fw_files = [fn for (fn, _) in find_all_firmwares(s["firmware_dir"])]

    if request.method == "POST":
        s["firmware_dir"]     = request.form.get("firmware_dir", s["firmware_dir"]).strip() or s["firmware_dir"]
        s["default_strategy"] = request.form.get("default_strategy", s["default_strategy"]).strip() or "latest"
        s["default_firmware"] = request.form.get("default_firmware", "").strip()
        try:
            s["events_cap"] = int(request.form.get("events_cap", s["events_cap"]))
        except Exception:
            pass
        save_settings(s)
        flash("ההגדרות נשמרו")
        return redirect(url_for("settings_page"))

    return render_template("settings.html", title="Settings", s=s, fw_files=fw_files, datetime=datetime)

# -------- OTA endpoint for ESP device --------
# GET /firmware.php?serial=...&device_id=...
@app.get("/firmware.php")
def firmware_php():
    serial = request.args.get("serial", "").strip()
    device_id = request.args.get("device_id", "").strip()
    if not serial:
        abort(400, "missing serial")

    chosen = choose_firmware_for_device(serial, device_id)
    if not chosen:
        abort(404, "no firmware available")

    evt = {
        "ts": now_iso(),
        "ip": request.headers.get("X-Forwarded-For", request.remote_addr or ""),
        "ua": request.headers.get("User-Agent", ""),
        "serial": serial,
        "device_id": device_id,
        "filename": chosen["filename"],
        "version": chosen["version"],
    }
    append_event(evt)
    record_device_touch(serial, device_id, chosen["filename"], chosen["version"])

    return send_file(
        chosen["path"],
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name=chosen["filename"]
    )

# -------- Misc --------
@app.get("/favicon.ico")
def favicon():
    abort(404)

@app.get("/healthz")
def healthz():
    return jsonify(ok=True, ts=now_iso())

# -------- Run --------
if __name__ == "__main__":
    s = load_settings()
    latest = find_latest_firmware(s["firmware_dir"])
    if latest:
        fn, ver = latest
        print(f"* Latest detected: {fn} (v{ver[0]}.{ver[1]}.{ver[2]}) in {s['firmware_dir']}")
    else:
        print(f"* No firmware files found in {s['firmware_dir']}")
    app.run(host="0.0.0.0", port=5000)
