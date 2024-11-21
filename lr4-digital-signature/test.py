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
        key_file_path = 'temp/test_file_sign_RSA_SHA256.pem'

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
        key_file_path = 'temp/test_file_sign_RSA_SHA256_changed_data.pem'

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
        key_file_path = 'temp/test_file_sign_RSA_SHA512.pem'

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
        key_file_path = 'temp/test_file_sign_RSA_SHA512_changed_data.pem'

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
        key_file_path = 'temp/test_file_sign_DSA.pem'

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
        key_file_path = 'temp/test_file_sign_DSA_changed_data.pem'

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
        key_file_path = 'temp/test_file_sign_ECDSA.pem'

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
        key_file_path = 'temp/test_file_sign_ECDSA_changed_data.pem'

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


def test_file_sign_GOST_34_10_2018_SHA256():
    try:
        file_path = 'temp/test_file_sign_GOST_34_10_2018.txt'
        signature_file_path = 'temp/test_file_sign_GOST_34_10_2018.sig'

        # Ensure the temp directory exists
        os.makedirs('temp', exist_ok=True)

        # Create a file with random bytes
        with open(file_path, 'wb') as f:
            f.write(random.randbytes(1024))

        # Sign the file
        sign_file(file_path, signature_file_path, None, 'GOST 34.10-2018 (SHA256)')

        # Verify the file
        assert verify_file(file_path, signature_file_path, 'GOST 34.10-2018 (SHA256)')
    finally:
        # Cleanup
        if os.path.exists(file_path):
            os.remove(file_path)
        if os.path.exists(signature_file_path):
            os.remove(signature_file_path)


def test_file_sign_GOST_34_10_2018_SHA256_changed_data():
    try:
        file_path = 'temp/test_file_sign_GOST_34_10_2018_SHA256_changed_data.txt'
        signature_file_path = 'temp/test_file_sign_GOST_34_10_2018_SHA256_changed_data.sig'

        # Ensure the temp directory exists
        os.makedirs('temp', exist_ok=True)

        # Create a file with random bytes
        with open(file_path, 'wb') as f:
            f.write(random.randbytes(1024))

        # Sign the file
        sign_file(file_path, signature_file_path, None, 'GOST 34.10-2018 (SHA256)')

        # Create a file with random bytes
        with open(file_path, 'wb') as f:
            f.write(random.randbytes(1024))

        # Verify the file
        assert (verify_file(file_path, signature_file_path,
                'GOST 34.10-2018 (SHA256)') == False)
    finally:
        # Cleanup
        if os.path.exists(file_path):
            os.remove(file_path)
        if os.path.exists(signature_file_path):
            os.remove(signature_file_path)


def test_file_sign_GOST_34_10_2018_SHA256_key_not_supported_msg():
    try:
        file_path = 'temp/test_file_sign_GOST_34_10_2018_SHA256_key_not_supported_msg.txt'
        key_file_path = 'temp/test_file_sign_GOST_34_10_2018_SHA256_key_not_supported_msg.pem'

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
        generate_key(key_file_path, 'GOST 34.10-2018 (SHA256)')

        # Reset stdout to its original value
        sys.stdout = sys.__stdout__

        # Get the captured output
        output = captured_output.getvalue()

        # Verify the output
        assert output == 'GOST 34.10-2018 (SHA256) key generation is not supported\n'
    finally:
        # Cleanup
        if os.path.exists(file_path):
            os.remove(file_path)


def test_file_sign_GOST_34_10_2012_SHA256():
    try:
        file_path = 'temp/test_file_sign_GOST_34_10_2012_SHA256.txt'
        signature_file_path = 'temp/test_file_sign_GOST_34_10_2012_SHA256.sig'
        key_file_path = 'temp/test_file_sign_GOST_34_10_2012_SHA256.pem'

        # Ensure the temp directory exists
        os.makedirs('temp', exist_ok=True)

        # Create a file with random bytes
        with open(file_path, 'wb') as f:
            f.write(random.randbytes(1024))

        # Generate a key
        generate_key(key_file_path, 'GOST 34.10-2012 (SHA256)')

        # Sign the file
        sign_file(file_path, signature_file_path,
                  key_file_path, 'GOST 34.10-2012 (SHA256)')

        # Verify the file
        assert verify_file(file_path, signature_file_path,
                           'GOST 34.10-2012 (SHA256)')
    finally:
        # Cleanup
        if os.path.exists(file_path):
            os.remove(file_path)
        if os.path.exists(signature_file_path):
            os.remove(signature_file_path)
        if os.path.exists(key_file_path):
            os.remove(key_file_path)


def test_file_sign_GOST_34_10_2012_SHA256_changed_data():
    try:
        file_path = 'temp/test_file_sign_GOST_34_10_2012_SHA256_changed_data.txt'
        signature_file_path = 'temp/test_file_sign_GOST_34_10_2012_SHA256_changed_data.sig'
        key_file_path = 'temp/test_file_sign_GOST_34_10_2012_SHA256_changed_data.pem'

        # Ensure the temp directory exists
        os.makedirs('temp', exist_ok=True)

        # Create a file with random bytes
        with open(file_path, 'wb') as f:
            f.write(random.randbytes(1024))

        # Generate a key
        generate_key(key_file_path, 'GOST 34.10-2012 (SHA256)')

        # Sign the file
        sign_file(file_path, signature_file_path,
                  key_file_path, 'GOST 34.10-2012 (SHA256)')

        # Create a file with random bytes
        with open(file_path, 'wb') as f:
            f.write(random.randbytes(1024))

        # Verify the file
        assert (verify_file(file_path, signature_file_path,
                'GOST 34.10-2012 (SHA256)') == False)
    finally:
        # Cleanup
        if os.path.exists(file_path):
            os.remove(file_path)
        if os.path.exists(signature_file_path):
            os.remove(signature_file_path)
        if os.path.exists(key_file_path):
            os.remove(key_file_path)


def test_file_sign_GOST_34_10_2012_STREEBOG256():
    try:
        file_path = 'temp/test_file_sign_GOST_34_10_2012_STREEBOG256.txt'
        signature_file_path = 'temp/test_file_sign_GOST_34_10_2012_STREEBOG256.sig'
        key_file_path = 'temp/test_file_sign_GOST_34_10_2012_STREEBOG256.pem'

        # Ensure the temp directory exists
        os.makedirs('temp', exist_ok=True)

        # Create a file with random bytes
        with open(file_path, 'wb') as f:
            f.write(random.randbytes(1024))

        # Generate a key
        generate_key(key_file_path, 'GOST 34.10-2012 (STREEBOG256)')

        # Sign the file
        sign_file(file_path, signature_file_path,
                  key_file_path, 'GOST 34.10-2012 (STREEBOG256)')

        # Verify the file
        assert verify_file(file_path, signature_file_path,
                           'GOST 34.10-2012 (STREEBOG256)')
    finally:
        # Cleanup
        if os.path.exists(file_path):
            os.remove(file_path)
        if os.path.exists(signature_file_path):
            os.remove(signature_file_path)
        if os.path.exists(key_file_path):
            os.remove(key_file_path)


def test_file_sign_GOST_34_10_2012_STREEBOG256_changed_data():
    try:
        file_path = 'temp/test_file_sign_GOST_34_10_2012_STREEBOG256_changed_data.txt'
        signature_file_path = 'temp/test_file_sign_GOST_34_10_2012_STREEBOG256_changed_data.sig'
        key_file_path = 'temp/test_file_sign_GOST_34_10_2012_STREEBOG256_changed_data.pem'

        # Ensure the temp directory exists
        os.makedirs('temp', exist_ok=True)

        # Create a file with random bytes
        with open(file_path, 'wb') as f:
            f.write(random.randbytes(1024))

        # Generate a key
        generate_key(key_file_path, 'GOST 34.10-2012 (STREEBOG256)')

        # Sign the file
        sign_file(file_path, signature_file_path,
                  key_file_path, 'GOST 34.10-2012 (STREEBOG256)')

        # Create a file with random bytes
        with open(file_path, 'wb') as f:
            f.write(random.randbytes(1024))

        # Verify the file
        assert (verify_file(file_path, signature_file_path,
                'GOST 34.10-2012 (STREEBOG256)') == False)
    finally:
        # Cleanup
        if os.path.exists(file_path):
            os.remove(file_path)
        if os.path.exists(signature_file_path):
            os.remove(signature_file_path)
        if os.path.exists(key_file_path):
            os.remove(key_file_path)

def test_file_sign_GOST_34_10_2012_STREEBOG512():
    try:
        file_path = 'temp/test_file_sign_GOST_34_10_2012_STREEBOG512.txt'
        signature_file_path = 'temp/test_file_sign_GOST_34_10_2012_STREEBOG512.sig'
        key_file_path = 'temp/test_file_sign_GOST_34_10_2012_STREEBOG512.pem'

        # Ensure the temp directory exists
        os.makedirs('temp', exist_ok=True)

        # Create a file with random bytes
        with open(file_path, 'wb') as f:
            f.write(random.randbytes(1024))

        # Generate a key
        generate_key(key_file_path, 'GOST 34.10-2012 (STREEBOG512)')

        # Sign the file
        sign_file(file_path, signature_file_path,
                  key_file_path, 'GOST 34.10-2012 (STREEBOG512)')

        # Verify the file
        assert verify_file(file_path, signature_file_path,
                           'GOST 34.10-2012 (STREEBOG512)')
    finally:
        # Cleanup
        if os.path.exists(file_path):
            os.remove(file_path)
        if os.path.exists(signature_file_path):
            os.remove(signature_file_path)
        if os.path.exists(key_file_path):
            os.remove(key_file_path)

def test_file_sign_GOST_34_10_2012_STREEBOG512_changed_data():
    try:
        file_path = 'temp/test_file_sign_GOST_34_10_2012_STREEBOG512_changed_data.txt'
        signature_file_path = 'temp/test_file_sign_GOST_34_10_2012_STREEBOG512_changed_data.sig'
        key_file_path = 'temp/test_file_sign_GOST_34_10_2012_STREEBOG512_changed_data.pem'

        # Ensure the temp directory exists
        os.makedirs('temp', exist_ok=True)

        # Create a file with random bytes
        with open(file_path, 'wb') as f:
            f.write(random.randbytes(1024))

        # Generate a key
        generate_key(key_file_path, 'GOST 34.10-2012 (STREEBOG512)')

        # Sign the file
        sign_file(file_path, signature_file_path,
                  key_file_path, 'GOST 34.10-2012 (STREEBOG512)')

        # Create a file with random bytes
        with open(file_path, 'wb') as f:
            f.write(random.randbytes(1024))

        # Verify the file
        assert (verify_file(file_path, signature_file_path,
                'GOST 34.10-2012 (STREEBOG512)') == False)
    finally:
        # Cleanup
        if os.path.exists(file_path):
            os.remove(file_path)
        if os.path.exists(signature_file_path):
            os.remove(signature_file_path)
        if os.path.exists(key_file_path):
            os.remove(key_file_path)

def test_file_sign_GOST_34_10_2012_SHA512():
    try:
        file_path = 'temp/test_file_sign_GOST_34_10_2012_SHA512.txt'
        signature_file_path = 'temp/test_file_sign_GOST_34_10_2012_SHA512.sig'
        key_file_path = 'temp/test_file_sign_GOST_34_10_2012_SHA512.pem'

        # Ensure the temp directory exists
        os.makedirs('temp', exist_ok=True)

        # Create a file with random bytes
        with open(file_path, 'wb') as f:
            f.write(random.randbytes(1024))

        # Generate a key
        generate_key(key_file_path, 'GOST 34.10-2012 (SHA512)')

        # Sign the file
        sign_file(file_path, signature_file_path,
                  key_file_path, 'GOST 34.10-2012 (SHA512)')

        # Verify the file
        assert verify_file(file_path, signature_file_path,
                           'GOST 34.10-2012 (SHA512)')
    finally:
        # Cleanup
        if os.path.exists(file_path):
            os.remove(file_path)
        if os.path.exists(signature_file_path):
            os.remove(signature_file_path)
        if os.path.exists(key_file_path):
            os.remove(key_file_path)