
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os
import hashlib

# 해시파일 생성 함수
def filehash(path, key):
    if not os.path.exists(path):
        print(f"[오류] 파일 없음: {path}")
        return

    key_bytes = key.encode('utf-8')
    key_bytes = key_bytes.ljust(16, b'0')[:16]

    h = hashlib.sha256()
    h.update(key_bytes)
    with open(path, 'rb') as f:
        while chunk := f.read(4096):
            h.update(chunk)

    hash_value = h.hexdigest()
    hash_path = path + ".hash"
    with open(hash_path, 'w') as f:
        f.write(hash_value)

    print(f"[해시 생성 완료] {hash_path}")

# 하나의 파일을 AES로 암호화
def aes(path, key):
    if not os.path.exists(path):
        return None

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
    filehash(out_path, key) #.Henc(암호화된 파일)에 대한 해시파일 생성
    return out_path

# 여러 파일을 암호화
def enc_aes(file_paths, key):
    encrypted_paths = []

    for path in file_paths:
        if not os.path.exists(path):
            continue


        result = aes(path, key)
        if result:
            encrypted_paths.append(result)

        if os.path.exists(path):
            os.remove(path)

    return encrypted_paths

# 복호화
def dec_aes(file_paths, key):
    decrypted_paths = []

    key_bytes = key.encode('utf-8')
    key_bytes = key_bytes.ljust(16, b'0')[:16]

    for path in file_paths:
        if not os.path.exists(path):
            continue

        out_path = path.replace(".Henc", "")
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

            decrypted_paths.append(out_path)

        except Exception as e:
            pass

        if os.path.exists(path):
            os.remove(path)
        if os.path.exists(path+".hash"):
            os.remove(path+".hash")

    return decrypted_paths

# ✅ 복호화 무결성 검사 함수
def isValidDec(hash_path, key):
    # 대응되는 암호화 파일 경로 유도
    enc_path = hash_path.replace(".hash", "")

    if not os.path.exists(enc_path):
        print(f"[무결성 검사 실패] 암호화 파일 없음: {enc_path}")
        return False

    if not os.path.exists(hash_path):
        print(f"[무결성 검사 실패] 해시 파일 없음: {hash_path}")
        return False

    # 키 보정 (사용자가 다른 키로 접근할 수 있으므로 동일하게 적용)
    key_bytes = key.encode('utf-8')
    key_bytes = key_bytes.ljust(16, b'0')[:16]

    # 암호화된 파일(.Henc)을 그대로 해시
    h = hashlib.sha256()
    h.update(key_bytes)
    with open(enc_path, 'rb') as f:
        while chunk := f.read(4096):
            h.update(chunk)
    new_hash = h.hexdigest()

    # 저장된 해시와 비교
    with open(hash_path, 'r') as f:
        stored_hash = f.read().strip()

    if new_hash == stored_hash:
        print(f"[무결성 검사 통과] {enc_path}")
        return True
    else:
        print(f"[무결성 검사 실패] {enc_path}")
        return False