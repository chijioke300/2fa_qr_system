"""
app.py
======
Authentication Server (Chapter 3) for the Two-Factor Authentication system
using Dynamic QR Codes and Cryptographic Encryption.

Authentication flow (matches the System Flowchart in Chapter 3):
  1.  User opens the login page.
  2.  User submits username + password  -> FIRST FACTOR (something you know).
  3.  Server validates credentials against the hashed password in the DB.
  4.  If incorrect  -> access denied.
  5.  If correct    -> server generates an encrypted, time-limited token,
                       converts it to a DYNAMIC QR code, and displays it.
  6.  User scans the QR with a phone -> SECOND FACTOR (something you have).
  7.  The phone hits /scan, the Verification Module decrypts and validates
      the token (signature, expiry, single-use).
  8.  The waiting login page (which is polling /status) detects success and
      grants access to the protected dashboard.

Run:  python app.py    then open  http://127.0.0.1:5000
"""

import io
import os
import time
import secrets
from datetime import datetime

import qrcode
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, send_file, jsonify, abort,
)

import database as db
from crypto_utils import TokenManager, generate_aes_key

# --------------------------------------------------------------------- #
# App + cryptographic setup
# --------------------------------------------------------------------- #
app = Flask(__name__)
# Secret key signs the browser session cookie. Generated fresh each run;
# for a stable deployment set it from an environment variable instead.
app.secret_key = os.environ.get("FLASK_SECRET", secrets.token_hex(32))

# AES key for the Encryption Module. Generated fresh each run for the demo.
# In production this would be loaded from a secure secret store.
AES_KEY = os.environ.get("AES_KEY", generate_aes_key().decode()).encode()
TOKEN_VALIDITY_SECONDS = 90  # the QR code expires after 90 seconds
tokens = TokenManager(AES_KEY, validity_seconds=TOKEN_VALIDITY_SECONDS)

db.init_db()


# --------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------- #
@app.route("/")
def index():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    """First factor: username + password."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Step 3-4: validate credentials.
        if not db.verify_user(username, password):
            db.add_log(username, "LOGIN_FAILED", "Incorrect username or password")
            return render_template("login.html", error="Incorrect username or password.")

        db.add_log(username, "PASSWORD_OK", "First factor passed")

        # Step 5: create a pending auth session and an encrypted dynamic token.
        session_id = secrets.token_urlsafe(24)
        issued = tokens.issue_token(session_id)
        db.create_auth_session(
            session_id, username, issued["token_hash"], issued["expires_at"]
        )

        # Remember (in the signed browser cookie) which login attempt this
        # browser is waiting on. The password is NOT kept.
        session["pending_sid"] = session_id
        session["pending_user"] = username

        # Stash the encrypted token only long enough to draw the QR image.
        app.config[f"token::{session_id}"] = issued["encrypted_token"]

        return redirect(url_for("verify_page", session_id=session_id))

    return render_template("login.html")


@app.route("/verify/<session_id>")
def verify_page(session_id):
    """Second factor: show the dynamic QR code and wait for it to be scanned."""
    if session.get("pending_sid") != session_id:
        return redirect(url_for("login"))

    auth = db.get_auth_session(session_id)
    if auth is None:
        return redirect(url_for("login"))

    seconds_left = max(0, auth["expires_at"] - int(time.time()))
    return render_template(
        "qr_verify.html",
        session_id=session_id,
        seconds_left=seconds_left,
    )


@app.route("/qr/<session_id>.png")
def qr_image(session_id):
    """
    QR Code Generator: render the encrypted token as a scannable QR.
    The QR encodes the /scan URL carrying the AES-encrypted token, so
    scanning it opens the verification endpoint on the user's phone.
    """
    if session.get("pending_sid") != session_id:
        abort(403)

    encrypted_token = app.config.get(f"token::{session_id}")
    if not encrypted_token:
        abort(404)

    # The phone needs to reach the server, so we build an absolute URL.
    scan_url = url_for("scan", token=encrypted_token, _external=True)

    img = qrcode.make(scan_url)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png")


@app.route("/scan")
def scan():
    """
    Verification Module: hit by the phone when the QR is scanned.
    Decrypts the token, checks the signature, expiry and single-use status,
    and marks the matching login session as verified.
    """
    encrypted_token = request.args.get("token", "")
    result = tokens.verify_token(encrypted_token)

    if not result["valid"]:
        db.add_log(None, "SCAN_REJECTED", result["reason"])
        return render_template("scan_result.html", ok=False, message=result["reason"])

    session_id = result["session_id"]
    auth = db.get_auth_session(session_id)

    if auth is None:
        return render_template("scan_result.html", ok=False, message="Unknown session.")
    if auth["used"]:
        # Single-use: an already-consumed token cannot be replayed.
        db.add_log(auth["username"], "SCAN_REJECTED", "Token already used (replay blocked)")
        return render_template("scan_result.html", ok=False, message="This QR code was already used.")

    db.mark_session_verified(session_id)
    db.add_log(auth["username"], "SECOND_FACTOR_OK", "QR scanned and token verified")
    return render_template("scan_result.html", ok=True, message="Verified! Return to your computer.")


@app.route("/status/<session_id>")
def status(session_id):
    """Polled by the login page to detect when the QR has been scanned."""
    if session.get("pending_sid") != session_id:
        return jsonify({"state": "invalid"})

    auth = db.get_auth_session(session_id)
    if auth is None:
        return jsonify({"state": "invalid"})
    if auth["verified"]:
        # Promote this browser to a fully authenticated session.
        session["authenticated_user"] = auth["username"]
        session.pop("pending_sid", None)
        return jsonify({"state": "verified"})
    if int(time.time()) > auth["expires_at"]:
        return jsonify({"state": "expired"})
    return jsonify({"state": "pending"})


@app.route("/dashboard")
def dashboard():
    """Protected page, reachable only after BOTH factors pass."""
    user = session.get("authenticated_user")
    if not user:
        return redirect(url_for("login"))
    
    # Get logs and format timestamps
    logs = db.get_recent_logs()
    for log in logs:
        log['created_at'] = datetime.utcfromtimestamp(log['created_at']).strftime('%Y-%m-%d %H:%M:%S')
    
    return render_template("dashboard.html", user=user, logs=logs)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    # host=0.0.0.0 lets a phone on the same Wi-Fi reach the server.
    app.run(host="0.0.0.0", port=5000, debug=True)