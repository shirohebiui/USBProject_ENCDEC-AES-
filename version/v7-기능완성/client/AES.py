
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

    h = hashlib.sha256() # SHA-256 해시 객체 생성
    h.update(key_bytes) # 키를 먼저 해시에 반영하여 키 종속적 해시 생성
    with open(path, 'rb') as f: # 파일 열기
        while chunk := f.read(4096): # 4KB씩 읽으며
            h.update(chunk) # 데이터 블록을 해시에 계속 반영
    hash_value = h.hexdigest() # 최종 해시값을 16진수 문자열로 반환
    
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

    iv = get_random_bytes(16) # 16바이트 길이의 무작위 IV(초기화 벡터) 생성
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv) # CBC 모드로 AES 암호화 객체 생성
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size)) # 평문에 패딩을 추가한 후 암호화 수행


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
                cipher = AES.new(key_bytes, AES.MODE_CBC, iv)  # 동일한 키와 IV로 복호화 객체 생성
                plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size) # 암호문을 복호화한 후 패딩 제거

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
    h = hashlib.sha256() # SHA-256 해시 객체 생성
    h.update(key_bytes) # 키를 먼저 해시에 반영하여 키 종속적 해시 생성
    with open(enc_path, 'rb') as f: # 파일 열기
        while chunk := f.read(4096): # 4KB씩 읽으며
            h.update(chunk) # 데이터 블록을 해시에 계속 반영
    new_hash = h.hexdigest() # 최종 해시값을 16진수 문자열로 반환

    # 저장된 해시와 비교
    with open(hash_path, 'r') as f:
        stored_hash = f.read().strip()

    if new_hash == stored_hash: # 새로 계산한 해시와 기존 해시를 비교하여 무결성 확인
        print(f"[무결성 검사 통과] {enc_path}")
        return True
    else:
        print(f"[무결성 검사 실패] {enc_path}")
        return False