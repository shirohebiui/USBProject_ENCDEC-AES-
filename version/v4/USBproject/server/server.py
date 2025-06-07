
import socket
import threading
import sqlite3
import pyotp
import secrets

HOST = '0.0.0.0'
PORT = 5000

def generate_aes_key():
    return secrets.token_hex(16)[:16]  # Generate 16-character AES key

def handle_client(conn, addr):
    print(f"[+] 연결됨: {addr}")
    try:
        data = conn.recv(1024).decode().strip()
        print(f"[{addr}] 수신: {data}")
        parts = data.split(',')

        if parts[0] == 'register':
            _, user_id, pw = parts
            totp_secret = pyotp.random_base32()
            aes_key = generate_aes_key()

            try:
                db = sqlite3.connect('users.db')
                cur = db.cursor()
                cur.execute("INSERT INTO users (id, pw, totp, aes_key) VALUES (?, ?, ?, ?)",
                            (user_id, pw, totp_secret, aes_key))
                db.commit()
                conn.sendall(f"TOTP:{totp_secret}".encode())
                print(f"[{addr}] 회원가입 완료 (AES key 저장)")
            except sqlite3.IntegrityError:
                conn.sendall("이미 존재하는 ID입니다.".encode())
            finally:
                db.close()

        elif parts[0] == 'login':
            _, user_id, pw, otp = parts

            db = sqlite3.connect('users.db')
            cur = db.cursor()
            cur.execute("SELECT pw, totp, aes_key FROM users WHERE id=?", (user_id,))
            result = cur.fetchone()
            db.close()

            if result:
                db_pw, db_totp, aes_key = result
                if db_pw == pw:
                    totp = pyotp.TOTP(db_totp)
                    if totp.verify(otp):
                        conn.sendall(f"success:{aes_key}".encode())
                        print(f"[{addr}] 로그인 성공")
                    else:
                        conn.sendall("OTP 인증 실패".encode())
                else:
                    conn.sendall("비밀번호 불일치".encode())
            else:
                conn.sendall("존재하지 않는 ID입니다.".encode())

    except Exception as e:
        print(f"[{addr}] 오류 발생: {e}")
        conn.sendall(f"서버 오류: {e}".encode())
    finally:
        conn.close()
        print(f"[-] 연결 종료: {addr}")

def start_server():
    print("[*] 서버 시작 중...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        print(f"[*] 서버 대기 중... ({HOST}:{PORT})")

        while True:
            conn, addr = server_socket.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr))
            thread.start()

if __name__ == "__main__":
    start_server()
