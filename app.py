from flask import Flask, request, jsonify
import sqlite3
import jwt
import time
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)
DB_FILE = "totally_not_my_privateKeys.db"

# ---------- DATABASE SETUP ----------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS keys(
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )
    """)

    conn.commit()
    conn.close()


# ---------- KEY GENERATION ----------
def generate_and_store_keys():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM keys")
    count = cursor.fetchone()[0]

    if count == 0:
        # Expired key
        expired_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        expired_pem = expired_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        cursor.execute(
            "INSERT INTO keys (key, exp) VALUES (?, ?)",
            (expired_pem, int(time.time()) - 10)
        )

        # Valid key
        valid_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        valid_pem = valid_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        cursor.execute(
            "INSERT INTO keys (key, exp) VALUES (?, ?)",
            (valid_pem, int(time.time()) + 3600)
        )

        conn.commit()

    conn.close()


# ---------- AUTH ENDPOINT ----------
@app.route("/auth", methods=["POST"])
def auth():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    current_time = int(time.time())

    if "expired" in request.args:
        cursor.execute(
            "SELECT kid, key FROM keys WHERE exp <= ? LIMIT 1",
            (current_time,)
        )
    else:
        cursor.execute(
            "SELECT kid, key FROM keys WHERE exp > ? LIMIT 1",
            (current_time,)
        )

    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "No key found"}), 400

    kid, private_pem = row

    private_key = serialization.load_pem_private_key(
        private_pem,
        password=None
    )

    token = jwt.encode(
        {"user": "userABC", "exp": current_time + 300},
        private_key,
        algorithm="RS256",
        headers={"kid": str(kid)}
    )

    return jsonify({"token": token})


# ---------- JWKS ENDPOINT ----------
@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    current_time = int(time.time())

    cursor.execute(
        "SELECT kid, key FROM keys WHERE exp > ?",
        (current_time,)
    )

    rows = cursor.fetchall()
    conn.close()

    keys = []

    for kid, private_pem in rows:
        private_key = serialization.load_pem_private_key(
            private_pem,
            password=None
        )

        public_key = private_key.public_key()
        numbers = public_key.public_numbers()

        e = base64.urlsafe_b64encode(
            numbers.e.to_bytes(3, byteorder="big")
        ).decode().rstrip("=")

        n = base64.urlsafe_b64encode(
            numbers.n.to_bytes(256, byteorder="big")
        ).decode().rstrip("=")

        keys.append({
            "kty": "RSA",
            "kid": str(kid),
            "use": "sig",
            "alg": "RS256",
            "n": n,
            "e": e
        })

    return jsonify({"keys": keys})


# ---------- START SERVER ----------
if __name__ == "__main__":
    init_db()
    generate_and_store_keys()
    app.run(host="0.0.0.0", port=8080)
