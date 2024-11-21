# pytest
import random
import os
import io
import sys

from sign import *


def test_file_sign_RSA_SHA256():
    try:
        file_path = 'temp/test_file_sign_RSA_SHA256.txt'
        signature_file_path = 'temp/test_file_sign_RSA_SHA256.sig'
        key_file_path = 'temp/test_file_sign_RSA_SHA256.key'

        # Ensure the temp directory exists
        os.makedirs('temp', exist_ok=True)

        # Create a file with random bytes
        with open(file_path, 'wb') as f:
            f.write(random.randbytes(1024))

        # Generate a key
        generate_key(key_file_path, 'RSA-SHA256')

        # Sign the file
        sign_file(file_path, signature_file_path, key_file_path, 'RSA-SHA256')

        # Verify the file
        assert verify_file(file_path, signature_file_path, 'RSA-SHA256')
    finally:
        # Cleanup
        if os.path.exists(file_path):
            os.remove(file_path)
        if os.path.exists(signature_file_path):
            os.remove(signature_file_path)
        if os.path.exists(key_file_path):
            os.remove(key_file_path)


def test_file_sign_RSA_SHA256_changed_data():
    try:
        file_path = 'temp/test_file_sign_RSA_SHA256_changed_data.txt'
        signature_file_path = 'temp/test_file_sign_RSA_SHA256_changed_data.sig'
        key_file_path = 'temp/test_file_sign_RSA_SHA256_changed_data.key'

        # Ensure the temp directory exists
        os.makedirs('temp', exist_ok=True)

        # Create a file with random bytes
        with open(file_path, 'wb') as f:
            f.write(random.randbytes(1024))

        # Generate a key
        generate_key(key_file_path, 'RSA-SHA256')

        # Sign the file
        sign_file(file_path, signature_file_path, key_file_path, 'RSA-SHA256')

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
        if os.path.exists(key_file_path):
            os.remove(key_file_path)


def test_file_sign_RSA_SHA512():
    try:
        file_path = 'temp/test_file_sign_RSA_SHA512.txt'
        signature_file_path = 'temp/test_file_sign_RSA_SHA512.sig'
        key_file_path = 'temp/test_file_sign_RSA_SHA512.key'

        # Ensure the temp directory exists
        os.makedirs('temp', exist_ok=True)

        # Create a file with random bytes
        with open(file_path, 'wb') as f:
            f.write(random.randbytes(1024))

        # Generate a key
        generate_key(key_file_path, 'RSA-SHA512')

        # Sign the file
        sign_file(file_path, signature_file_path, key_file_path, 'RSA-SHA512')

        # Verify the file
        assert verify_file(file_path, signature_file_path, 'RSA-SHA512')
    finally:
        # Cleanup
        if os.path.exists(file_path):
            os.remove(file_path)
        if os.path.exists(signature_file_path):
            os.remove(signature_file_path)
        if os.path.exists(key_file_path):
            os.remove(key_file_path)


def test_file_sign_RSA_SHA512_changed_data():
    try:
        file_path = 'temp/test_file_sign_RSA_SHA512_changed_data.txt'
        signature_file_path = 'temp/test_file_sign_RSA_SHA512_changed_data.sig'
        key_file_path = 'temp/test_file_sign_RSA_SHA512_changed_data.key'

        # Ensure the temp directory exists
        os.makedirs('temp', exist_ok=True)

        # Create a file with random bytes
        with open(file_path, 'wb') as f:
            f.write(random.randbytes(1024))

        # Generate a key
        generate_key(key_file_path, 'RSA-SHA512')

        # Sign the file
        sign_file(file_path, signature_file_path, key_file_path, 'RSA-SHA512')

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
        if os.path.exists(key_file_path):
            os.remove(key_file_path)


def test_file_sign_DSA():
    try:
        file_path = 'temp/test_file_sign_DSA.txt'
        signature_file_path = 'temp/test_file_sign_DSA.sig'
        key_file_path = 'temp/test_file_sign_DSA.key'

        # Ensure the temp directory exists
        os.makedirs('temp', exist_ok=True)

        # Create a file with random bytes
        with open(file_path, 'wb') as f:
            f.write(random.randbytes(1024))

        # Generate a key
        generate_key(key_file_path, 'DSA')

        # Sign the file
        sign_file(file_path, signature_file_path, key_file_path, 'DSA')

        # Verify the file
        assert verify_file(file_path, signature_file_path, 'DSA')
    finally:
        # Cleanup
        if os.path.exists(file_path):
            os.remove(file_path)
        if os.path.exists(signature_file_path):
            os.remove(signature_file_path)
        if os.path.exists(key_file_path):
            os.remove(key_file_path)


def test_file_sign_DSA_changed_data():
    try:
        file_path = 'temp/test_file_sign_DSA_changed_data.txt'
        signature_file_path = 'temp/test_file_sign_DSA_changed_data.sig'
        key_file_path = 'temp/test_file_sign_DSA_changed_data.key'

        # Ensure the temp directory exists
        os.makedirs('temp', exist_ok=True)

        # Create a file with random bytes
        with open(file_path, 'wb') as f:
            f.write(random.randbytes(1024))

        # Generate a key
        generate_key(key_file_path, 'DSA')

        # Sign the file
        sign_file(file_path, signature_file_path, key_file_path, 'DSA')

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
        if os.path.exists(key_file_path):
            os.remove(key_file_path)


def test_file_sign_ECDSA():
    try:
        file_path = 'temp/test_file_sign_ECDSA.txt'
        signature_file_path = 'temp/test_file_sign_ECDSA.sig'
        key_file_path = 'temp/test_file_sign_ECDSA.key'

        # Ensure the temp directory exists
        os.makedirs('temp', exist_ok=True)

        # Create a file with random bytes
        with open(file_path, 'wb') as f:
            f.write(random.randbytes(1024))

        # Generate a key
        generate_key(key_file_path, 'ECDSA')

        # Sign the file
        sign_file(file_path, signature_file_path, key_file_path, 'ECDSA')

        # Verify the file
        assert verify_file(file_path, signature_file_path, 'ECDSA')
    finally:
        # Cleanup
        if os.path.exists(file_path):
            os.remove(file_path)
        if os.path.exists(signature_file_path):
            os.remove(signature_file_path)
        if os.path.exists(key_file_path):
            os.remove(key_file_path)


def test_file_sign_ECDSA_changed_data():
    try:
        file_path = 'temp/test_file_sign_ECDSA_changed_data.txt'
        signature_file_path = 'temp/test_file_sign_ECDSA_changed_data.sig'
        key_file_path = 'temp/test_file_sign_ECDSA_changed_data.key'

        # Ensure the temp directory exists
        os.makedirs('temp', exist_ok=True)

        # Create a file with random bytes
        with open(file_path, 'wb') as f:
            f.write(random.randbytes(1024))

        # Generate a key
        generate_key(key_file_path, 'ECDSA')

        # Sign the file
        sign_file(file_path, signature_file_path, key_file_path, 'ECDSA')

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
        if os.path.exists(key_file_path):
            os.remove(key_file_path)


def test_file_sign_GOST_34_10_2018():
    try:
        file_path = 'temp/test_file_sign_GOST_34_10_2018.txt'
        signature_file_path = 'temp/test_file_sign_GOST_34_10_2018.sig'

        # Ensure the temp directory exists
        os.makedirs('temp', exist_ok=True)

        # Create a file with random bytes
        with open(file_path, 'wb') as f:
            f.write(random.randbytes(1024))

        # Sign the file
        sign_file(file_path, signature_file_path, None, 'GOST 34.10-2018')

        # Verify the file
        assert verify_file(file_path, signature_file_path, 'GOST 34.10-2018')
    finally:
        # Cleanup
        if os.path.exists(file_path):
            os.remove(file_path)
        if os.path.exists(signature_file_path):
            os.remove(signature_file_path)


def test_file_sign_GOST_34_10_2018_changed_data():
    try:
        file_path = 'temp/test_file_sign_GOST_34_10_2018_changed_data.txt'
        signature_file_path = 'temp/test_file_sign_GOST_34_10_2018_changed_data.sig'

        # Ensure the temp directory exists
        os.makedirs('temp', exist_ok=True)

        # Create a file with random bytes
        with open(file_path, 'wb') as f:
            f.write(random.randbytes(1024))

        # Sign the file
        sign_file(file_path, signature_file_path, None, 'GOST 34.10-2018')

        # Create a file with random bytes
        with open(file_path, 'wb') as f:
            f.write(random.randbytes(1024))

        # Verify the file
        assert (verify_file(file_path, signature_file_path,
                'GOST 34.10-2018') == False)
    finally:
        # Cleanup
        if os.path.exists(file_path):
            os.remove(file_path)
        if os.path.exists(signature_file_path):
            os.remove(signature_file_path)


def test_file_sign_GOST_34_10_2018_key_not_supported_msg():
    try:
        file_path = 'temp/test_file_sign_GOST_34_10_2018_key_not_supported_msg.txt'
        key_file_path = 'temp/test_file_sign_GOST_34_10_2018_key_not_supported_msg.key'

        # Ensure the temp directory exists
        os.makedirs('temp', exist_ok=True)

        # Create a file with random bytes
        with open(file_path, 'wb') as f:
            f.write(random.randbytes(1024))

        # Create a StringIO object to capture the output
        captured_output = io.StringIO()

        # Redirect stdout to the StringIO object
        sys.stdout = captured_output

        # Generate a key
        generate_key(key_file_path, 'GOST 34.10-2018')

        # Reset stdout to its original value
        sys.stdout = sys.__stdout__

        # Get the captured output
        output = captured_output.getvalue()

        # Verify the output
        assert output == 'GOST 34.10-2018 key generation is not supported\n'
    finally:
        # Cleanup
        if os.path.exists(file_path):
            os.remove(file_path)
