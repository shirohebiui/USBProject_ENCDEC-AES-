from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes
import os

# 🔐 하나의 파일을 AES로 암호화
def aes(path, key):
    if not os.path.exists(path):
        print("❌ 파일 없음:", path)
        return None

    # 키를 16바이트로 보정
    key_bytes = key.encode('utf-8')
    key_bytes = key_bytes.ljust(16, b'0')[:16]

    out_path = path + ".Henc"
    if os.path.exists(out_path):
        os.remove(out_path)

    with open(path, "rb") as f_in:
        plaintext = f_in.read()

    iv = get_random_bytes(16)
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    with open(out_path, "wb") as f_out:
        f_out.write(iv + ciphertext)

    print("✅ 암호화 완료:", out_path)
    return out_path


# 🔁 여러 파일을 암호화
def enc_aes(file_paths, key):
    print("[enc_aes 실행] key =", key)
    encrypted_paths = []

    for path in file_paths:
        result = aes(path, key)
        if result:
            encrypted_paths.append(result)
        
        #원본 파일 삭제
        if os.path.exists(path):
            os.remove(path)

    return encrypted_paths

def dec_aes(file_paths, key):
    print("[dec_aes 실행] key =", key)
    decrypted_paths = []

    # 키 준비
    key_bytes = key.encode('utf-8')
    key_bytes = key_bytes.ljust(16, b'0')[:16]

    for path in file_paths:
        if not os.path.exists(path):
            print("❌ 복호화 대상 파일 없음:", path)
            continue

        out_path = path.replace(".Henc", "")  # 확장자 제거
        if os.path.exists(out_path):
            os.remove(out_path)

        try:
            with open(path, "rb") as f_in:
                data = f_in.read()
                iv = data[:16]
                ciphertext = data[16:]

                cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
                plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

            with open(out_path, "wb") as f_out:
                f_out.write(plaintext)

            print("✅ 복호화 완료:", out_path)
            decrypted_paths.append(out_path)

        except Exception as e:
            print("❌ 복호화 실패:", path, "| 이유:", e)
        #원본 파일 삭제
        if os.path.exists(path):
            os.remove(path)

    return decrypted_paths