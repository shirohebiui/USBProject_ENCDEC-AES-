from flask import Flask, request, jsonify
import pymysql
import secrets
import base64

app = Flask(__name__)

# ─────────────────────────────────────────────
# 🔧 설정
DB_CONFIG = {
    "host": "192.168.160.1",     # Windows MySQL IP
    "user": "root",
    "password": "1234",
    "database": "user_auth",
    "cursorclass": pymysql.cursors.DictCursor
}

# ─────────────────────────────────────────────
# 🔑 AES 키 생성 함수
def generate_aes_key(length=16):
    return base64.b64encode(secrets.token_bytes(length)).decode("utf-8")

# ─────────────────────────────────────────────
# 🔌 DB 연결 함수
def get_connection():
    return pymysql.connect(**DB_CONFIG)

# ─────────────────────────────────────────────
# 🔐 사용자 등록 API
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"status": "fail", "message": "Missing username or password"}), 400

    aes_key = generate_aes_key()

    try:
        with get_connection() as conn, conn.cursor() as cursor:
            cursor.execute("SELECT id FROM users WHERE username=%s", (username,))
            if cursor.fetchone():
                return jsonify({"status": "fail", "message": "Username already exists"}), 409

            cursor.execute(
                "INSERT INTO users (username, password, aes_key) VALUES (%s, %s, %s)",
                (username, password, aes_key)
            )
            conn.commit()
            return jsonify({"status": "ok", "message": "User registered", "key": aes_key})

    except Exception as e:
        return jsonify({"status": "fail", "message": f"Server error: {str(e)}"}), 500

# ─────────────────────────────────────────────
# 🔑 키 요청 API
@app.route("/get_key", methods=["POST"])
def get_key():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"status": "fail", "message": "Missing username or password"}), 400

    try:
        with get_connection() as conn, conn.cursor() as cursor:
            cursor.execute(
                "SELECT aes_key FROM users WHERE username=%s AND password=%s",
                (username, password)
            )
            result = cursor.fetchone()
            if result:
                return jsonify({"status": "ok", "key": result["aes_key"]})
            else:
                return jsonify({"status": "fail", "message": "Invalid credentials"}), 401

    except Exception as e:
        return jsonify({"status": "fail", "message": f"Server error: {str(e)}"}), 500

# ─────────────────────────────────────────────
# 🚀 서버 실행
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
