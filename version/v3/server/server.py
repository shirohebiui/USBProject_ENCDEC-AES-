import socket
import threading
import hashlib
import pyotp
import sqlite3
import mysql.connector

HOST = '0.0.0.0'
PORT = 5000

# 비밀번호를 SHA-256 해시로 변환
def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

# 사용자 등록 함수: TOTP 시크릿 키 생성 후 DB에 저장
def register_user(id, pw):
    totp_secret = pyotp.random_base32()  # TOTP 키 생성
    hashed_pw = hash_pw(pw)              # 비밀번호 해싱
    conn = sqlite3.connect('users.db')
    cur = conn.cursor()
    cur.execute("INSERT OR REPLACE INTO users (id, password_hash, totp_secret) VALUES (?, ?, ?)",
                (id, hashed_pw, totp_secret))
    conn.commit()
    conn.close()
    return totp_secret  # 클라이언트에게 전송

# 로그인 검증 함수: 비밀번호와 OTP 코드 확인
def verify_login(id, pw, otp_code):
    conn = sqlite3.connect('users.db')
    cur = conn.cursor()
    cur.execute("SELECT password_hash, totp_secret FROM users WHERE id = ?", (id,))
    row = cur.fetchone()
    conn.close()

    if not row:
        return False  # ID 없음

    hashed_pw, totp_secret = row
    if hashed_pw != hash_pw(pw):
        return False  # 비밀번호 불일치

    # OTP 코드 검증
    totp = pyotp.TOTP(totp_secret)
    return totp.verify(otp_code)

# 클라이언트 처리 함수: register 또는 login 요청 처리
def handle_client(conn, addr):
    print(f"[+] 연결됨: {addr}")
    db = mysql.connector.connect(
        host="localhost",
        user="root",
        password="1234",
        database="usb_project"
    )
    cursor = db.cursor()
    try:
        while True:
            data = conn.recv(1024).decode()
            if not data:
                break

            parts = data.split(",")
            action = parts[0]

            if action == "register":
                id = parts[1]
                pw = parts[2]

                # ID 중복 확인
                cursor.execute("SELECT * FROM users WHERE id=%s", (id,))
                if cursor.fetchone():
                    print(f"[SERVER] 이미 존재하는 ID입니다: {id}")
                    conn.sendall("이미 존재하는 ID입니다.".encode())
                    continue

                # TOTP 키 생성 및 저장
                totp_key = pyotp.random_base32()
                cursor.execute("INSERT INTO users (id, pw, totp) VALUES (%s, %s, %s)", (id, pw, totp_key))
                db.commit()

                # 클라이언트에 TOTP 키 전송
                conn.sendall(f"TOTP:{totp_key}".encode())

            elif action == "login":
                id = parts[1]
                pw = parts[2]
                otp = parts[3]

                # 사용자 정보 조회
                cursor.execute("SELECT pw, totp FROM users WHERE id=%s", (id,))
                result = cursor.fetchone()

                if not result:
                    conn.sendall("존재하지 않는 ID입니다.".encode())
                    continue

                db_pw, totp_key = result

                if pw != db_pw:
                    conn.sendall("비밀번호가 일치하지 않습니다.".encode())
                    continue

                # TOTP 코드 검증
                totp = pyotp.TOTP(totp_key)
                if not totp.verify(otp):
                    conn.sendall("OTP 코드가 유효하지 않습니다.".encode())
                    continue

                # 로그인 성공
                conn.sendall("success".encode())
            else:
                conn.sendall("알 수 없는 명령입니다.".encode())

    except Exception as e:
        print(f"[!] 예외 발생: {e}")
    finally:
        conn.close()
        print(f"[-] 연결 종료: {addr}")


# 서버 시작 함수: 연결 수신 및 스레드 처리
def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"[+] Server listening on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr)).start()

# 메인 함수: 서버 실행
if __name__ == "__main__":
    start_server()