#!/usr/bin/env python3
"""
encrypt_keys.py
Шифрует приватные ключи (строки, например hex-ключи) в JSON-файл.
Использует scrypt -> AES-GCM. Результат: JSON-массив записей с полями:
  id, meta, salt, nonce, ciphertext
Файл создаётся с правами 0o600.
"""
import argparse
import json
import os
import base64
from getpass import getpass
from typing import List, Dict
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Параметры по умолчанию для scrypt (можно адаптировать для вашей системы)
SCRYPT_DEFAULT = {
    "salt_len": 16,
    "length": 32,     # длина производного ключа в байтах (AES-256 -> 32)
    "n": 2**14,       # CPU/memory cost
    "r": 8,
    "p": 1
}
NONCE_LEN = 12  # AESGCM рекомендует 12 байт nonce

def derive_key(password: bytes, salt: bytes, length: int, n: int, r: int, p: int) -> bytes:
    kdf = Scrypt(salt=salt, length=length, n=n, r=r, p=p)
    return kdf.derive(password)

def encrypt_value(plaintext: str, password: str, sparams: Dict) -> Dict:
    salt = os.urandom(sparams["salt_len"])
    key = derive_key(password.encode("utf-8"), salt,
                     sparams["length"], sparams["n"], sparams["r"], sparams["p"])
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_LEN)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return {
        "ciphertext": base64.b64encode(ct).decode("ascii"),
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii")
    }

def load_input_keys(input_path: str) -> List[str]:
    if input_path == "-":
        import sys
        return [line.strip() for line in sys.stdin if line.strip()]
    with open(input_path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

def main():
    p = argparse.ArgumentParser(description="Encrypt private keys into JSON using scrypt + AES-GCM")
    p.add_argument("-i", "--input", default=None,
                   help="Input file with one private key per line, '-' for stdin. If omitted, interactive entry.")
    p.add_argument("-o", "--output", default="encrypted_keys.json", help="Output JSON file")
    p.add_argument("--scrypt-n", type=int, default=SCRYPT_DEFAULT["n"], help="scrypt N parameter")
    p.add_argument("--scrypt-r", type=int, default=SCRYPT_DEFAULT["r"], help="scrypt r parameter")
    p.add_argument("--scrypt-p", type=int, default=SCRYPT_DEFAULT["p"], help="scrypt p parameter")
    p.add_argument("--salt-len", type=int, default=SCRYPT_DEFAULT["salt_len"], help="salt length in bytes")
    p.add_argument("--key-len", type=int, default=SCRYPT_DEFAULT["length"], help="derived key length in bytes")
    p.add_argument("--force", action="store_true", help="Overwrite output if exists")
    args = p.parse_args()

    password = getpass("Password to encrypt with: ")
    password_confirm = getpass("Confirm password: ")
    if password != password_confirm:
        print("Passwords do not match. Aborting.")
        return

    if args.input:
        keys = load_input_keys(args.input)
    else:
        print("Enter private keys one per line. Empty line to finish.")
        keys = []
        while True:
            s = input("Key: ").strip()
            if not s:
                break
            keys.append(s)

    if not keys:
        print("No keys provided. Exiting.")
        return

    sparams = {
        "salt_len": args.salt_len,
        "length": args.key_len,
        "n": args.scrypt_n,
        "r": args.scrypt_r,
        "p": args.scrypt_p
    }

    out_records = []
    for idx, k in enumerate(keys, start=1):
        enc = encrypt_value(k, password, sparams)
        rec = {
            "id": f"key{idx}",
            "meta": {
                "algo": "AES-GCM",
                "kdf": "scrypt",
                "scrypt_params": sparams
            },
            **enc
        }
        out_records.append(rec)

    if os.path.exists(args.output) and not args.force:
        print(f"Output file {args.output} exists. Use --force to overwrite.")
        return

    tmp = args.output + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(out_records, f, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, args.output)
    print(f"Encrypted {len(out_records)} keys -> {args.output} (mode 0600)")

if __name__ == "__main__":
    main()
