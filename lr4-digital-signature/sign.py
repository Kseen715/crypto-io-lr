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
from Crypto.PublicKey import RSA, DSA, ECC
from Crypto.Signature import pkcs1_15, DSS
import ksilorama


import GOST_R_34_10_2018

msg_valid_signature = \
    '[SIGNATURE] ' \
    + ksilorama.Fore.HEX('#22BB66') \
    + ksilorama.Style.ITALIC \
    + 'Signature is valid' \
    + ksilorama.Style.RESET_ALL
msg_invalid_signature = \
    '[SIGNATURE] ' \
    + ksilorama.Fore.RED \
    + ksilorama.Style.BLINK \
    + ksilorama.Style.BRIGHT \
    + ksilorama.Style.INVERTED \
    + 'Invalid signature' \
    + ksilorama.Style.RESET_ALL


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
    
def generate_key(key_path: Path, alg: str) -> None:
    if alg == 'RSA-SHA256':
        key = RSA.generate(2048)
        with Path(key_path).open('wb') as f:
            f.write(key.export_key())
    elif alg == 'RSA-SHA512':
        key = RSA.generate(4096)
        with Path(key_path).open('wb') as f:
            f.write(key.export_key())
    elif alg == 'DSA':
        key = DSA.generate(2048)
        with Path(key_path).open('wb') as f:
            f.write(key.export_key())
    elif alg == 'ECDSA':
        key = ECC.generate(curve='P-256')
        with Path(key_path).open('wb') as f:
            f.write(key.export_key(format='PEM').encode())
    elif alg == 'GOST 34.10-2018':
        print('GOST 34.10-2018 key generation is not supported')


def sign_file(file: Path, signature_file: Path, key_path: Path, alg: str) -> None:
    # keep key in the begining of sig file
    if alg == 'RSA-SHA256':
        key = RSA.import_key(Path(key_path).read_bytes())
        with Path(file).open('rb') as f:
            data = f.read()
        signature = sign_RSA_SHA256(data, key)
        with Path(signature_file).open('wb') as f:
            key_data = key.publickey().export_key()
            f.write(len(key_data).to_bytes(4, 'big'))
            f.write(key_data)
            f.write(signature)
    elif alg == 'RSA-SHA512':
        key = RSA.import_key(Path(key_path).read_bytes())
        with Path(file).open('rb') as f:
            data = f.read()
        signature = sign_RSA_SHA512(data, key)
        with Path(signature_file).open('wb') as f:
            key_data = key.publickey().export_key()
            f.write(len(key_data).to_bytes(4, 'big'))
            f.write(key_data)
            f.write(signature)
    elif alg == 'DSA':
        key = DSA.import_key(Path(key_path).read_bytes())
        with Path(file).open('rb') as f:
            data = f.read()
        signature = sign_DSA(data, key)
        with Path(signature_file).open('wb') as f:
            key_data = key.publickey().export_key()
            f.write(len(key_data).to_bytes(4, 'big'))
            f.write(key_data)
            f.write(signature)
    elif alg == 'ECDSA':
        key = ECC.import_key(Path(key_path).read_bytes())
        with Path(file).open('rb') as f:
            data = f.read()
        h = SHA256.new(data)
        signer = DSS.new(key, 'fips-186-3')
        signature = signer.sign(h)
        with Path(signature_file).open('wb') as f:
            key_data = key.public_key().export_key(format='PEM')
            f.write(len(key_data).to_bytes(4, 'big'))
            f.write(key_data.encode())
            f.write(signature)
    elif alg == 'GOST 34.10-2018':
        GOST_R_34_10_2018.elgamal_ecc_sign(file, signature_file)


def verify_file(file: Path, signature_file: Path, alg: str) -> bool:
    if alg == 'RSA-SHA256':
        with Path(signature_file).open('rb') as f:
            key_len = int.from_bytes(f.read(4), 'big')
            public_key = RSA.import_key(f.read(key_len))
            signature = f.read()
        with Path(file).open('rb') as f:
            data = f.read()
        if verify_RSA_SHA256(data, signature, public_key):
            return True
        else:
            return False
    elif alg == 'RSA-SHA512':
        with Path(signature_file).open('rb') as f:
            key_len = int.from_bytes(f.read(4), 'big')
            key = RSA.import_key(f.read(key_len))
            signature = f.read()
        with Path(file).open('rb') as f:
            data = f.read()
        if verify_RSA_SHA512(data, signature, key):
            return True
        else:
            return False
    elif alg == 'DSA':
        with Path(signature_file).open('rb') as f:
            key_len = int.from_bytes(f.read(4), 'big')
            key = DSA.import_key(f.read(key_len))
            signature = f.read()
        with Path(file).open('rb') as f:
            data = f.read()
        if verify_DSA(data, signature, key):
            return True
        else:
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
            return True
        except (ValueError, TypeError):
            return False
    elif alg == 'GOST 34.10-2018':
        return GOST_R_34_10_2018.elgamal_ecc_verify(file, signature_file)

algs = ['RSA-SHA256', 'RSA-SHA512', 'DSA', 'ECDSA', 'GOST 34.10-2018']

if __name__ == '__main__':

    description = \
        ksilorama.Fore.HEX('#EE9944') \
        + ksilorama.Style.ITALIC \
        + f'Sign or verify a file using a digital signature' \
        + ksilorama.Style.RESET_ALL
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        'command', choices=['sign', 'verify', 'keygen'],
        help='Command to execute')
    parser.add_argument('file', type=Path, help='File to sign', nargs='?')
    parser.add_argument('signature', type=Path, help='Signature file')
    # key is optional for verification
    parser.add_argument('key', type=Path, help='Key file', nargs='?')
    parser.add_argument(
        '-a', '--alg', type=str,
        choices=algs, required=True,
        help='Algorithm to use')
    args = parser.parse_args()

    try:
        if args.command == 'verify':
            res = verify_file(args.file, args.signature, args.alg)
            if res:
                print(msg_valid_signature)
            else:
                print(msg_invalid_signature)
        elif args.command == 'sign':
            sign_file(args.file, args.signature, args.key, args.alg)
            print(f'Signed {ksilorama.Style.UNDERLINE}{args.file}'
                  + f'{ksilorama.Style.RESET_ALL} with '
                  + f'{ksilorama.Style.UNDERLINE}{args.alg}'
                  + f'{ksilorama.Style.RESET_ALL} algorithm. Signature saved '
                  + f'to {ksilorama.Style.UNDERLINE}{args.signature}'
                  + f'{ksilorama.Style.RESET_ALL}')
        elif args.command == 'keygen':
            generate_key(args.signature, args.alg)
            print(f'Generated key for {ksilorama.Style.UNDERLINE}{args.alg}'
                  + f'{ksilorama.Style.RESET_ALL} algorithm. Key saved to '
                  + f'{ksilorama.Style.UNDERLINE}{args.signature}'
                  + f'{ksilorama.Style.RESET_ALL}')

    except Exception as e:
        print(e, file=sys.stderr)
        sys.exit()
