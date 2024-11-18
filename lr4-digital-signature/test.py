# pytest
import random
import os

import pytest

from sign import *


def test_file_sign_RSA_SHA256():
    try:
        file_path = 'temp/test_file_sign_RSA_SHA256.txt'
        signature_file_path = 'temp/test_file_sign_RSA_SHA256.sig'

        # Ensure the temp directory exists
        os.makedirs('temp', exist_ok=True)

        # Remove files if they exist
        if os.path.exists(file_path):
            os.remove(file_path)
        if os.path.exists(signature_file_path):
            os.remove(signature_file_path)

        # Create a file with random bytes
        with open(file_path, 'wb') as f:
            f.write(random.randbytes(1024))

        # Sign the file
        sign_file(file_path, signature_file_path, 'RSA-SHA256')

        # Verify the file
        assert verify_file(file_path, signature_file_path, 'RSA-SHA256')
    finally:
        # Cleanup
        if os.path.exists(file_path):
            os.remove(file_path)
        if os.path.exists(signature_file_path):
            os.remove(signature_file_path)


def test_file_sign_RSA_SHA256_changed_data():
    try:
        file_path = 'temp/test_file_sign_RSA_SHA256_changed_data.txt'
        signature_file_path = 'temp/test_file_sign_RSA_SHA256_changed_data.sig'

        # Ensure the temp directory exists
        os.makedirs('temp', exist_ok=True)

        # Remove files if they exist
        if os.path.exists(file_path):
            os.remove(file_path)
        if os.path.exists(signature_file_path):
            os.remove(signature_file_path)

        # Create a file with random bytes
        with open(file_path, 'wb') as f:
            f.write(random.randbytes(1024))

        # Sign the file
        sign_file(file_path, signature_file_path, 'RSA-SHA256')
        
        # Create a file with random bytes
        with open(file_path, 'wb') as f:
            f.write(random.randbytes(1024))

        # Verify the file
        assert (verify_file(file_path, signature_file_path, 'RSA-SHA256') == False)
    finally:
        # Cleanup
        if os.path.exists(file_path):
            os.remove(file_path)
        if os.path.exists(signature_file_path):
            os.remove(signature_file_path)


def test_file_sign_RSA_SHA512():
    try:
        file_path = 'temp/test_file_sign_RSA_SHA512.txt'
        signature_file_path = 'temp/test_file_sign_RSA_SHA512.sig'

        # Ensure the temp directory exists
        os.makedirs('temp', exist_ok=True)

        # Remove files if they exist
        if os.path.exists(file_path):
            os.remove(file_path)
        if os.path.exists(signature_file_path):
            os.remove(signature_file_path)

        # Create a file with random bytes
        with open(file_path, 'wb') as f:
            f.write(random.randbytes(1024))

        # Sign the file
        sign_file(file_path, signature_file_path, 'RSA-SHA512')

        # Verify the file
        assert verify_file(file_path, signature_file_path, 'RSA-SHA512')
    finally:
        # Cleanup
        if os.path.exists(file_path):
            os.remove(file_path)
        if os.path.exists(signature_file_path):
            os.remove(signature_file_path)


def test_file_sign_RSA_SHA512_changed_data():
    try:
        file_path = 'temp/test_file_sign_RSA_SHA512_changed_data.txt'
        signature_file_path = 'temp/test_file_sign_RSA_SHA512_changed_data.sig'

        # Ensure the temp directory exists
        os.makedirs('temp', exist_ok=True)

        # Remove files if they exist
        if os.path.exists(file_path):
            os.remove(file_path)
        if os.path.exists(signature_file_path):
            os.remove(signature_file_path)

        # Create a file with random bytes
        with open(file_path, 'wb') as f:
            f.write(random.randbytes(1024))

        # Sign the file
        sign_file(file_path, signature_file_path, 'RSA-SHA512')

        # Create a file with random bytes
        with open(file_path, 'wb') as f:
            f.write(random.randbytes(1024))

        # Verify the file
        assert (verify_file(file_path, signature_file_path, 'RSA-SHA512') == False)
    finally:
        # Cleanup
        if os.path.exists(file_path):
            os.remove(file_path)
        if os.path.exists(signature_file_path):
            os.remove(signature_file_path)


def test_file_sign_DSA():
    try:
        file_path = 'temp/test_file_sign_DSA.txt'
        signature_file_path = 'temp/test_file_sign_DSA.sig'

        # Ensure the temp directory exists
        os.makedirs('temp', exist_ok=True)

        # Remove files if they exist
        if os.path.exists(file_path):
            os.remove(file_path)
        if os.path.exists(signature_file_path):
            os.remove(signature_file_path)

        # Create a file with random bytes
        with open(file_path, 'wb') as f:
            f.write(random.randbytes(1024))

        # Sign the file
        sign_file(file_path, signature_file_path, 'DSA')

        # Verify the file
        assert verify_file(file_path, signature_file_path, 'DSA')
    finally:
        # Cleanup
        if os.path.exists(file_path):
            os.remove(file_path)
        if os.path.exists(signature_file_path):
            os.remove(signature_file_path)


def test_file_sign_DSA_changed_data():
    try:
        file_path = 'temp/test_file_sign_DSA_changed_data.txt'
        signature_file_path = 'temp/test_file_sign_DSA_changed_data.sig'

        # Ensure the temp directory exists
        os.makedirs('temp', exist_ok=True)

        # Remove files if they exist
        if os.path.exists(file_path):
            os.remove(file_path)
        if os.path.exists(signature_file_path):
            os.remove(signature_file_path)

        # Create a file with random bytes
        with open(file_path, 'wb') as f:
            f.write(random.randbytes(1024))

        # Sign the file
        sign_file(file_path, signature_file_path, 'DSA')

        # Create a file with random bytes
        with open(file_path, 'wb') as f:
            f.write(random.randbytes(1024))

        # Verify the file
        assert (verify_file(file_path, signature_file_path, 'DSA') == False)
    finally:
        # Cleanup
        if os.path.exists(file_path):
            os.remove(file_path)
        if os.path.exists(signature_file_path):
            os.remove(signature_file_path)


def test_file_sign_ECDSA():
    try:
        file_path = 'temp/test_file_sign_ECDSA.txt'
        signature_file_path = 'temp/test_file_sign_ECDSA.sig'

        # Ensure the temp directory exists
        os.makedirs('temp', exist_ok=True)

        # Remove files if they exist
        if os.path.exists(file_path):
            os.remove(file_path)
        if os.path.exists(signature_file_path):
            os.remove(signature_file_path)

        # Create a file with random bytes
        with open(file_path, 'wb') as f:
            f.write(random.randbytes(1024))

        # Sign the file
        sign_file(file_path, signature_file_path, 'ECDSA')

        # Verify the file
        assert verify_file(file_path, signature_file_path, 'ECDSA')
    finally:
        # Cleanup
        if os.path.exists(file_path):
            os.remove(file_path)
        if os.path.exists(signature_file_path):
            os.remove(signature_file_path)


def test_file_sign_ECDSA_changed_data():
    try:
        file_path = 'temp/test_file_sign_ECDSA_changed_data.txt'
        signature_file_path = 'temp/test_file_sign_ECDSA_changed_data.sig'

        # Ensure the temp directory exists
        os.makedirs('temp', exist_ok=True)

        # Remove files if they exist
        if os.path.exists(file_path):
            os.remove(file_path)
        if os.path.exists(signature_file_path):
            os.remove(signature_file_path)

        # Create a file with random bytes
        with open(file_path, 'wb') as f:
            f.write(random.randbytes(1024))

        # Sign the file
        sign_file(file_path, signature_file_path, 'ECDSA')

        # Create a file with random bytes
        with open(file_path, 'wb') as f:
            f.write(random.randbytes(1024))

        # Verify the file
        assert (verify_file(file_path, signature_file_path, 'ECDSA') == False)
    finally:
        # Cleanup
        if os.path.exists(file_path):
            os.remove(file_path)
        if os.path.exists(signature_file_path):
            os.remove(signature_file_path)
