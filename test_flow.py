"""Smoke test: walks the entire 2FA flow without a browser."""
import re
import app as application

client = application.app.test_client()

print("1. GET /login")
r = client.get("/login")
assert r.status_code == 200 and b"Secure Login" in r.data, "login page failed"
print("   ok")

print("2. POST /login with WRONG password -> should be rejected")
r = client.post("/login", data={"username": "student", "password": "wrong"})
assert b"Incorrect username or password" in r.data, "wrong password not rejected"
print("   ok (access denied)")

print("3. POST /login with CORRECT password -> should redirect to /verify")
r = client.post("/login", data={"username": "student", "password": "password123"})
assert r.status_code == 302 and "/verify/" in r.headers["Location"], "correct login did not redirect"
sid = r.headers["Location"].split("/verify/")[1]
print(f"   ok (session {sid[:12]}...)")

print("4. GET the QR image")
r = client.get(f"/qr/{sid}.png")
assert r.status_code == 200 and r.mimetype == "image/png", "QR image failed"
print(f"   ok ({len(r.data)} bytes PNG)")

print("5. Status before scan -> pending")
import json
r = client.get(f"/status/{sid}")
assert json.loads(r.data)["state"] == "pending", "status should be pending"
print("   ok (pending)")

# Grab the encrypted token the server stashed for the QR.
encrypted = application.app.config[f"token::{sid}"]

print("6. Simulate phone scanning the QR -> /scan")
r = client.get(f"/scan?token={encrypted}")
assert b"Verified" in r.data, "scan did not verify"
print("   ok (token verified)")

print("7. Replay the same QR token -> must be blocked")
r = client.get(f"/scan?token={encrypted}")
assert b"already used" in r.data, "replay was NOT blocked"
print("   ok (replay blocked)")

print("8. Status after scan -> verified")
r = client.get(f"/status/{sid}")
assert json.loads(r.data)["state"] == "verified", "status should be verified"
print("   ok (verified)")

print("9. Access protected /dashboard")
r = client.get("/dashboard")
assert b"You are authenticated with two factors" in r.data, "dashboard not granted"
print("   ok (access granted)")

print("10. Tampered/forged token -> rejected")
r = client.get("/scan?token=gAAAAAfake_forged_token_value")
assert b"Invalid or tampered token" in r.data, "forged token not rejected"
print("   ok (forgery rejected)")

print("\nALL TESTS PASSED")
