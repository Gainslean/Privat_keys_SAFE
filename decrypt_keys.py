#!/usr/bin/env python3
"""
decrypt_keys.py
Дешифрует JSON, созданный encrypt_keys.py и выводит приватные ключи.
"""
import argparse
import json
import base64
from getpass import getpass
from typing import Dict, List
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def derive_key(password: bytes, salt: bytes, length: int, n: int, r: int, p: int) -> bytes:
    kdf = Scrypt(salt=salt, length=length, n=n, r=r, p=p)
    return kdf.derive(password)

def decrypt_record(rec: Dict, password: str) -> str:
    try:
        salt = base64.b64decode(rec["salt"])
        nonce = base64.b64decode(rec["nonce"])
        ct = base64.b64decode(rec["ciphertext"])
    except Exception as e:
        raise ValueError(f"Invalid encoding in record: {e}")

    sparams = rec.get("meta", {}).get("scrypt_params")
    if not sparams:
        # бекпорт: если нет meta, предполагаем стандартные параметры (опасно, но более совместимо)
        raise ValueError("Missing scrypt_params in record.meta")

    key = derive_key(password.encode("utf-8"), salt,
                     sparams["length"], sparams["n"], sparams["r"], sparams["p"])
    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(nonce, ct, None)
    return pt.decode("utf-8")

def main():
    p = argparse.ArgumentParser(description="Decrypt JSON file created by encrypt_keys.py")
    p.add_argument("-i", "--input", default="encrypted_keys.json", help="Input JSON file")
    p.add_argument("-o", "--output", default=None, help="Optional output file (one key per line). If omitted, prints to stdout.")
    args = p.parse_args()

    password = getpass("Password to decrypt with: ")

    with open(args.input, "r", encoding="utf-8") as f:
        data = json.load(f)

    decrypted = []
    for rec in data:
        try:
            pk = decrypt_record(rec, password)
            decrypted.append({"id": rec.get("id"), "privkey": pk})
        except Exception as e:
            print(f"[!] Failed to decrypt {rec.get('id')}: {e}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as outf:
            for r in decrypted:
                outf.write(r["privkey"] + "\n")
        print(f"Wrote {len(decrypted)} keys to {args.output}")
    else:
        for r in decrypted:
            print(f"{r['id']}: {r['privkey']}")

if __name__ == "__main__":
    main()
