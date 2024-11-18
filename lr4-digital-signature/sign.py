# Algs
# - RSA-SHA256
# - RSA-SHA512
# - DSA
# - ECDSA
# - ГОСТ 34.10-2018
import argparse
import sys
from pathlib import Path
from typing import Optional
from Crypto.Hash import SHA256, SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Signature import DSS
from Crypto.PublicKey import DSA
from Crypto.PublicKey import ECC


import ksilorama


def sign_RSA_SHA256(data: bytes, key: RSA.RsaKey) -> bytes:
    h = SHA256.new(data)
    return pkcs1_15.new(key).sign(h)


def verify_RSA_SHA256(data: bytes, signature: bytes, key: RSA.RsaKey) -> bool:
    h = SHA256.new(data)
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


def sign_RSA_SHA512(data: bytes, key: RSA.RsaKey) -> bytes:
    h = SHA512.new(data)
    return pkcs1_15.new(key).sign(h)


def verify_RSA_SHA512(data: bytes, signature: bytes, key: RSA.RsaKey) -> bool:
    h = SHA512.new(data)
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


def sign_DSA(data: bytes, key: DSA.DsaKey) -> bytes:
    h = SHA256.new(data)
    return DSS.new(key, 'fips-186-3').sign(h)


def verify_DSA(data: bytes, signature: bytes, key: DSA.DsaKey) -> bool:
    h = SHA256.new(data)
    try:
        DSS.new(key, 'fips-186-3').verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


def sign_file(file: Path, signature_file: Path, alg: str) -> None:
    # keep key in the begining of sig file
    if alg == 'RSA-SHA256':
        key = RSA.generate(2048)

        with Path(file).open('rb') as f:
            data = f.read()
        signature = sign_RSA_SHA256(data, key)
        with Path(signature_file).open('wb') as f:
            key_len = len(key.export_key())
            f.write(key_len.to_bytes(4, 'big'))
            f.write(key.export_key())
            f.write(signature)
    elif alg == 'RSA-SHA512':
        key = RSA.generate(4096)
        with Path(file).open('rb') as f:
            data = f.read()
        signature = sign_RSA_SHA512(data, key)
        with Path(signature_file).open('wb') as f:
            key_len = len(key.export_key())
            f.write(key_len.to_bytes(4, 'big'))
            f.write(key.export_key())
            f.write(signature)
    elif alg == 'DSA':
        key = DSA.generate(2048)
        with Path(file).open('rb') as f:
            data = f.read()
        signature = sign_DSA(data, key)
        with Path(signature_file).open('wb') as f:
            key_len = len(key.export_key())
            f.write(key_len.to_bytes(4, 'big'))
            f.write(key.export_key())
            f.write(signature)
    elif alg == 'ECDSA':
        key = ECC.generate(curve='P-256')
        with Path(file).open('rb') as f:
            data = f.read()
        h = SHA256.new(data)
        signer = DSS.new(key, 'fips-186-3')
        signature = signer.sign(h)
        with Path(signature_file).open('wb') as f:
            key_pem = key.export_key(format='PEM')
            key_len = len(key_pem)
            f.write(key_len.to_bytes(4, 'big'))
            f.write(key_pem.encode())
            f.write(signature)


def verify_file(file: Path, signature_file: Path, alg: str) -> bool:
    if alg == 'RSA-SHA256':
        with Path(signature_file).open('rb') as f:
            key_len = int.from_bytes(f.read(4), 'big')
            key = RSA.import_key(f.read(key_len))
            signature = f.read()
        with Path(file).open('rb') as f:
            data = f.read()
        if verify_RSA_SHA256(data, signature, key):
            print(ksilorama.Fore.GREEN + 'Signature is valid' +
                  ksilorama.Style.RESET_ALL)
            return True
        else:
            print(ksilorama.Fore.RED + 'Signature is invalid' +
                  ksilorama.Style.RESET_ALL)
            return False
    elif alg == 'RSA-SHA512':
        with Path(signature_file).open('rb') as f:
            key_len = int.from_bytes(f.read(4), 'big')
            key = RSA.import_key(f.read(key_len))
            signature = f.read()
        with Path(file).open('rb') as f:
            data = f.read()
        if verify_RSA_SHA512(data, signature, key):
            print(ksilorama.Fore.GREEN + 'Signature is valid' +
                  ksilorama.Style.RESET_ALL)
            return True
        else:
            print(ksilorama.Fore.RED + 'Signature is invalid' +
                  ksilorama.Style.RESET_ALL)
            return False
    elif alg == 'DSA':
        with Path(signature_file).open('rb') as f:
            key_len = int.from_bytes(f.read(4), 'big')
            key = DSA.import_key(f.read(key_len))
            signature = f.read()
        with Path(file).open('rb') as f:
            data = f.read()
        if verify_DSA(data, signature, key):
            print(ksilorama.Fore.GREEN + 'Signature is valid' +
                  ksilorama.Style.RESET_ALL)
            return True
        else:
            print(ksilorama.Fore.RED + 'Signature is invalid' +
                  ksilorama.Style.RESET_ALL)
            return False
    elif alg == 'ECDSA':
        with Path(signature_file).open('rb') as f:
            key_len = int.from_bytes(f.read(4), 'big')
            key = ECC.import_key(f.read(key_len))
            signature = f.read()
        with Path(file).open('rb') as f:
            data = f.read()
        h = SHA256.new(data)
        verifier = DSS.new(key, 'fips-186-3')
        try:
            verifier.verify(h, signature)
            print(ksilorama.Fore.GREEN + 'Signature is valid' +
                  ksilorama.Style.RESET_ALL)
            return True
        except (ValueError, TypeError):
            print(ksilorama.Fore.RED + 'Signature is invalid' +
                  ksilorama.Style.RESET_ALL)
            return False


if __name__ == '__main__':
    pass

    # parser = argparse.ArgumentParser(description='Sign a file')
    # parser.add_argument('file', type=Path, help='File to sign')
    # parser.add_argument('key', type=Path, help='Key file')
    # parser.add_argument('signature', type=Path, help='Signature file')
    # parser.add_argument('--alg', type=str, default='sha256', help='Algorithm')
    # args = parser.parse_args()

    # try:
    #     sign_file(args.file, args.key, args.signature, args.hash)
    # except Exception as e:
    #     print(e, file=sys.stderr)
    #     sys.exit()
