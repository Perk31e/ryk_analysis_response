#!/usr/bin/env python3
import sys
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

'''
현재 상황 요약
-알고 있는것-
1. 암호화 알고리즘: AES
2. 복호화 키: d8975c4d-19f9-4182-9794-ddea001be5a5.aes
3. 키 사이즈: AES-256 (32바이트)
4. 복호화대상: FLAG.txt.ryk

-모르는것-
1. 사용된 AES 모드: ECB, CBC, CFB, OFB, CTR, GCM
2. 초기화 벡터, Nonce, 태그, 패딩
    => CBC, CFB, OFB, CTR, GCM 모두 IV가 필요하다.
    => CTR, GCM 모두 Nonce가 필요하다
	=> ECB, CBC 패딩 필요

예외: GCM모드는 난수, 태그를 알고 있다. (암호문의 맨 앞부분 및 뒷부분으로 대체 가능)

-결론-
ECB, GCM 모드로 복호화 시도
'''

def read_key_256(key_path: str):
    with open(key_path, "r", encoding="utf-8") as f:
        s = f.read()
    s = s.replace(" ", "").replace("\n", "").replace("\r", "").replace("\t", "")
    s = s.removeprefix("0x").removeprefix("0X")
    key = bytes.fromhex(s)
    if len(key) != 32:
        raise ValueError("This is not AES-256 key(32byte key length required).")
    return key

def save_result(base: str, mode: str, pt: bytes) -> str:
    '''
    파일 내 저장된 한글 글자 깨짐 현상을 고려하여 디코드 및 인코딩 수행
    1. UTF-8로 디코딩 시도
    2. 실패하면 CP949로 디코딩 시도
    3. 둘 다 실패하면 .bin으로 저장
    '''
    file_name, file_ext = os.path.splitext(base)
    txt_out = f"{file_name}{file_ext}.dec.{mode}.txt"
    bin_out = f"{file_name}{file_ext}.dec.{mode}.bin"
    
    for enc in ("utf-8", "cp949"):
        try:
            text = pt.decode(enc)
            with open(txt_out, "w", encoding=enc) as f:
                f.write(text)
            print(f"[{mode}] 텍스트({enc}) 저장: {txt_out}")
            print(f"[{mode}] 내용: {text}")
            return txt_out
        except UnicodeDecodeError:
            continue
    
    with open(bin_out, "wb") as f:
        f.write(pt)
    print(f"[{mode}] 텍스트 디코딩 실패 → 바이너리 저장: {bin_out}")
    return bin_out

def mod_ecb(key: bytes, ct: bytes, ct_len: int, base: str):
    '''
    ecb는 입력 데이터가 16바이트의 배수가 아닐 때 패딩이 필요하다.
    즉, 암호화된 값은 16바이트 배수여야 한다.
    '''
    if ct_len % 16 != 0:
        print(f"ECB 불가: 암호문 크기({ct_len})가 16의 배수가 아님")
        return
    
    try:
        cipher = AES.new(key, AES.MODE_ECB)
        pt = cipher.decrypt(ct)
        
        # 복호화 후, 패딩 제거 시도
        try:
            pt_unpadded = unpad(pt, AES.block_size)
            save_result(base, "ecb", pt_unpadded)
        except ValueError:
            print("ECB: 패딩 제거 실패, 원본 저장")
            save_result(base, "ecb_raw", pt)
            
    except Exception as e:
        print(f"ECB 복호화 실패: {e}")

def mod_gcm(key: bytes, ct: bytes, ct_len: int, base: str):
    '''
    gcm 암호문 구조
    gcm_ciphertext = nonce(12) + cp_mid + tag(16)
    cp_mid = nonce, tag를 제외한 나머지 암호문
    '''
    if ct_len <= 12 + 16: 
        print("GCM: 암호문이 너무 짧음")
        return
    
    nonce = ct[:12]
    tag = ct[-16:]
    cp_mid = ct[12:-16]
    
    if len(cp_mid) <= 0: 
        print("GCM: 실제 데이터가 없음")
        return
    
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        pt = cipher.decrypt_and_verify(cp_mid, tag)
        save_result(base, "GCM", pt)
    except Exception as e:
        print(f"[GCM] 복호화 실패: {e}")

def main():
    if len(sys.argv) != 3:
        print("Usage: python decrypt.py <key_file> <ciphertext_file>")
        sys.exit(1)
    
    key_path = sys.argv[1]
    ct_path = sys.argv[2]

    try:
        key = read_key_256(key_path)
    except Exception as e:
        print(f"[키 오류] {e}")
        sys.exit(2)
    
    # 파일 읽기
    with open(ct_path, "rb") as f:
        ct = f.read()
    
    ct_len = len(ct)

    base = ct_path
    print(f"- AES: 256-bit (키 {len(key)} bytes OK)")
    print(f"- 암호문 크기: {ct_len} bytes")
    
    mod_ecb(key, ct, ct_len, base)
    mod_gcm(key, ct, ct_len, base)
    print("== 시도 완료 ==")

if __name__ == "__main__":
    main()