#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Python 3.12.6

import os
import argparse
from hashlib import sha256

from Crypto.Cipher import DES3
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import colorama


# ✨ 3DES ECB -------------------------------------------------------------------

class DES3_ECB_EDE:
    def __init__(self, key1, key2, key3):
        self.key = key1 + key2 + key3
        assert len(self.key) == 24, f"Key must be 24 bytes long, got {
            len(self.key)}"

    def encrypt(self, data):
        data = pad(data, DES3.block_size)
        cipher = DES3.new(self.key, DES3.MODE_ECB)
        data = cipher.encrypt(data)
        return data

    def decrypt(self, data):
        cipher = DES3.new(self.key, DES3.MODE_ECB)
        data = cipher.decrypt(data)
        data = unpad(data, DES3.block_size)
        return data

# ✨ 3DES Inner CBC -------------------------------------------------------------
# во внутреннем CBC сцепление блоков происходит на каждом из трех этапов
# шифрования

class DES3_INNER_CBC_EDE:
    def __init__(self, key1, key2, key3, iv):
        self.key1 = key1
        self.key2 = key2
        self.key3 = key3
        self.iv = iv

    def encrypt(self, data):
        data = pad(data, DES.block_size)
        cipher = DES.new(self.key1, DES.MODE_CBC, self.iv)
        data = cipher.encrypt(data)
        cipher = DES.new(self.key2, DES.MODE_CBC, self.iv)
        data = cipher.encrypt(data)
        cipher = DES.new(self.key3, DES.MODE_CBC, self.iv)
        data = cipher.encrypt(data)
        return data

    def decrypt(self, data):
        cipher = DES.new(self.key3, DES.MODE_CBC, self.iv)
        data = cipher.decrypt(data)
        cipher = DES.new(self.key2, DES.MODE_CBC, self.iv)
        data = cipher.decrypt(data)
        cipher = DES.new(self.key1, DES.MODE_CBC, self.iv)
        data = cipher.decrypt(data)
        data = unpad(data, DES.block_size)
        return data

# ✨ 3DES Outer CBC -------------------------------------------------------------
# во внешнем CBC сцепление работает так, как будто все три этапа шифрования
# являются одним

class DES3_OUTER_CBC_EDE:
    def __init__(self, key1, key2, key3, iv):
        self.key = key1 + key2 + key3
        assert len(self.key) == 24, f"Key must be 24 bytes long, got {
            len(self.key)}"
        self.iv = iv

    def encrypt(self, data):
        data = pad(data, DES.block_size)
        cipher_encrypt = DES3.new(self.key, DES3.MODE_CBC, self.iv)
        data = cipher_encrypt.encrypt(data)
        return data

    def decrypt(self, data):
        cipher_decrypt = DES3.new(self.key, DES3.MODE_CBC, self.iv)
        data = cipher_decrypt.decrypt(data)
        data = unpad(data, DES.block_size)
        return data

# ✨ 3DES with pad --------------------------------------------------------------
# В режиме 3DES with pad между первым и вторым, а также между вторым и третьим
# шифрованиями текст дополняется строкой случайных битов длинной полблока.
# Таким образом обеспечивается перекрытие блоков шифрования

class DES3_ECB_PAD_EDE:
    def __init__(self, key1, key2, key3):
        self.key1 = key1
        self.key2 = key2
        self.key3 = key3

    def __add_random_bits(self, data, block_size):
        random_bits = get_random_bytes(block_size // 2)
        return random_bits + data

    def __remove_random_bits(self, data, block_size):
        return data[block_size // 2:]

    def encrypt(self, data):
        # Padding the data to be a multiple of the block size
        data = pad(data, DES.block_size)
        # Encrypt with the first key
        cipher1 = DES.new(self.key1, DES.MODE_ECB)
        data = cipher1.encrypt(data)
        # Add random bits between first and second encryption
        data = self.__add_random_bits(data, DES.block_size)
        # Padding the data to be a multiple of the block size
        data = pad(data, DES.block_size)
        # Encrypt with the second key
        cipher2 = DES.new(self.key2, DES.MODE_ECB)
        data = cipher2.encrypt(data)
        # Add random bits between second and third encryption
        data = self.__add_random_bits(data, DES.block_size)
        # Padd the data to be a multiple of the block size
        data = pad(data, DES.block_size)
        # Encrypt with the third key
        cipher3 = DES.new(self.key3, DES.MODE_ECB)
        data = cipher3.encrypt(data)
        return data

    def decrypt(self, data):
        # Decrypt with the third key
        cipher3 = DES.new(self.key3, DES.MODE_ECB)
        data = cipher3.decrypt(data)
        # Unpad the decrypted data
        data = unpad(data, DES.block_size)
        # Remove random bits between second and third encryption from the start
        # of the data
        data = self.__remove_random_bits(
            data, DES.block_size)
        # Decrypt with the second key
        cipher2 = DES.new(self.key2, DES.MODE_ECB)
        data = cipher2.decrypt(data)
        # Unpad the decrypted data
        data = unpad(data, DES.block_size)
        # Remove random bits between first and second encryption
        data = self.__remove_random_bits(
            data, DES.block_size)
        # Decrypt with the first key
        cipher1 = DES.new(self.key1, DES.MODE_ECB)
        data = cipher1.decrypt(data)
        # Unpad the decrypted data
        data = unpad(data, DES.block_size)
        return data


def test():
    '''
    Test all the implemented 3DES modes
    
    Raises:
        Exception: If any of the tests fail
    '''
    data = get_random_bytes(1533)
    key = get_random_bytes(24)
    d3_ecb_ede = DES3_ECB_EDE(key[0:8], key[8:16], key[16:24])
    ciphertext = d3_ecb_ede.encrypt(data)
    plaintext = d3_ecb_ede.decrypt(ciphertext)

    if sha256(data).digest() != sha256(plaintext).digest():
        raise Exception("3DES ECB EDE failed")
    else:
        print(f"{colorama.Fore.GREEN}3DES ECB EDE passed{
            colorama.Style.RESET_ALL}")
    
    # Data to encrypt
    data = get_random_bytes(1533)
    # Keys and IVs for each DES operation
    key = get_random_bytes(24)
    iv = get_random_bytes(8)  # Single IV for inner CBC
    d3_inner_cbc = DES3_INNER_CBC_EDE(key[0:8], key[8:16], key[16:24], iv)
    ciphertext = d3_inner_cbc.encrypt(data)
    plaintext = d3_inner_cbc.decrypt(ciphertext)

    if sha256(data).digest() != sha256(plaintext).digest():
        raise Exception("3DES Inner CBC EDE failed")
    else:
        print(f"{colorama.Fore.GREEN}3DES Inner CBC EDE passed{
            colorama.Style.RESET_ALL}")
    
    # Data to be encrypted
    data = get_random_bytes(1533)
    # Key must be either 24 bytes long
    key = get_random_bytes(24)
    # Generate a random IV
    iv = get_random_bytes(DES3.block_size)
    d3_outer_cbc = DES3_OUTER_CBC_EDE(key[0:8], key[8:16], key[16:24], iv)
    ciphertext = d3_outer_cbc.encrypt(data)
    plaintext = d3_outer_cbc.decrypt(ciphertext)

    if sha256(data).digest() != sha256(plaintext).digest():
        raise Exception("3DES Outer CBC EDE failed")
    else:
        print(f"{colorama.Fore.GREEN}3DES Outer CBC EDE passed{
            colorama.Style.RESET_ALL}")
    
    # Data to be encrypted
    data = get_random_bytes(1533)
    # Keys must be 8 bytes long each
    key = get_random_bytes(24)
    d3_ecb_pad_ede = DES3_ECB_PAD_EDE(key[0:8], key[8:16], key[16:24])
    ciphertext = d3_ecb_pad_ede.encrypt(data)
    plaintext = d3_ecb_pad_ede.decrypt(ciphertext)

    if sha256(data).digest() != sha256(plaintext).digest():
        raise Exception("3DES with pad failed")
    else:
        print(f"{colorama.Fore.GREEN}3DES with pad passed{
            colorama.Style.RESET_ALL}")

def save_keys(key1, key2, key3, filename):
    '''
    Save the 3 keys to a file
    
    Args:
        key1 (bytes): The first key
        key2 (bytes): The second key
        key3 (bytes): The third key
        filename (str): The name of the file to save the keys to
    '''
    with open(filename, "wb") as f:
        f.write(key1)
        f.write(key2)
        f.write(key3)

def read_keys(filename):
    '''
    Read the 3 keys from a file
    
    Args:
        filename (str): The name of the file to read the keys from
    
    Returns:
        tuple: The 3 keys
    '''

def generate_keys():
    '''
    Generate 3 random keys
    
    Returns:
        tuple: The 3 keys
    '''
    key1 = get_random_bytes(8)
    key2 = get_random_bytes(8)
    key3 = get_random_bytes(8)
    return key1, key2, key3

def save_iv(iv, filename):
    '''
    Save the IV to a file
    
    Args:
        iv (bytes): The IV
        filename (str): The name of the file to save the IV to
    '''
    with open(filename, "wb") as f:
        f.write(iv)

def read_iv(filename):
    '''
    Read the IV from a file
    
    Args:
        filename (str): The name of the file to read the IV from
    
    Returns:
        bytes: The IV
    '''
    with open(filename, "rb") as f:
        iv = f.read()
    return iv

def generate_iv():
    '''
    Generate a random IV
    
    Returns:
        bytes: The IV
    '''
    return get_random_bytes(DES3.block_size)

def encrypt_file(input_file, output_file, mode, key1, key2, key3, iv=None):
    '''
    Encrypt a file using 3DES
    
    Args:
        input_file (str): The name of the file to encrypt
        output_file (str): The name of the file to save the encrypted data to
        mode (str): The mode of operation to use
        key1 (bytes): The first key
        key2 (bytes): The second key
        key3 (bytes): The third key
        iv (bytes): The IV
    '''
    with open(input_file, "rb") as f:
        data = f.read()
    if mode == "ecb_ede":
        cipher = DES3_ECB_EDE(key1, key2, key3)
    elif mode == "inner_cbc_ede":
        cipher = DES3_INNER_CBC_EDE(key1, key2, key3, iv)
    elif mode == "outer_cbc_ede":
        cipher = DES3_OUTER_CBC_EDE(key1, key2, key3, iv)
    elif mode == "ecb_pad_ede":
        cipher = DES3_ECB_PAD_EDE(key1, key2, key3)
    else:
        raise ValueError(f"Invalid mode: {mode}")
    ciphertext = cipher.encrypt(data)
    with open(output_file, "wb") as f:
        f.write(ciphertext)

def decrypt_file(input_file, output_file, mode, key1, key2, key3, iv=None):
    '''
    Decrypt a file using 3DES
    
    Args:
        input_file (str): The name of the file to decrypt
        output_file (str): The name of the file to save the decrypted data to
        mode (str): The mode of operation to use
        key1 (bytes): The first key
        key2 (bytes): The second key
        key3 (bytes): The third key
        iv (bytes): The IV
    '''
    with open(input_file, "rb") as f:
        data = f.read()
    if mode == "ecb_ede":
        cipher = DES3_ECB_EDE(key1, key2, key3)
    elif mode == "inner_cbc_ede":
        cipher = DES3_INNER_CBC_EDE(key1, key2, key3, iv)
    elif mode == "outer_cbc_ede":
        cipher = DES3_OUTER_CBC_EDE(key1, key2, key3, iv)
    elif mode == "ecb_pad_ede":
        cipher = DES3_ECB_PAD_EDE(key1, key2, key3)
    else:
        raise ValueError(f"Invalid mode: {mode}")
    plaintext = cipher.decrypt(data)
    with open(output_file, "wb") as f:
        f.write(plaintext)


def main():
    parser = argparse.ArgumentParser(
        description="3DES modes of operation")
    parser.add_argument(
        "-t", "--test", action="store_true", help="Run the tests")
    parser.add_argument(
        "-y", "--yes", action="store_true", help="Skip the confirmation")
    args = parser.parse_args()
    if args.test:
        test()

    

if __name__ == "__main__":
    test()
