#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Python 3.12.6

import os
import argparse

from Crypto.Cipher import DES3
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


# ✨ 3DES ECB -------------------------------------------------------------------

class DES3_ECB_EDE:
    def __init__(self, key1, key2, key3):
        self.key = key1 + key2 + key3
        assert len(self.key) == 24, f"Key must be 24 bytes long, got {len(self.key)}"

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


data = b"Secret Message"
key = get_random_bytes(24)

d3_ecb_ede = DES3_ECB_EDE(key[0:8], key[8:16], key[16:24])

ciphertext = d3_ecb_ede.encrypt(data)
plaintext = d3_ecb_ede.decrypt(ciphertext)

print("Ciphertext:", ciphertext)
print("Plaintext:", plaintext)

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


# Data to encrypt
data = b"Secret Message"

# Keys and IVs for each DES operation
key = get_random_bytes(24)
iv = get_random_bytes(8)  # Single IV for inner CBC

d3_inner_cbc=DES3_INNER_CBC_EDE(key[0:8], key[8:16], key[16:24], iv)

ciphertext=d3_inner_cbc.encrypt(data)
plaintext=d3_inner_cbc.decrypt(ciphertext)

print("Ciphertext:", ciphertext)
print("Plaintext:", plaintext)

# ✨ 3DES Outer CBC -------------------------------------------------------------
# во внешнем CBC сцепление работает так, как будто все три этапа шифрования
# являются одним


class DES3_OUTER_CBC_EDE:
    def __init__(self, key1, key2, key3, iv):
        self.key=key1 + key2 + key3
        assert len(self.key) == 24, f"Key must be 24 bytes long, got {
            len(self.key)}"
        self.iv=iv

    def encrypt(self, data):
        data=pad(data, DES.block_size)
        cipher_encrypt=DES3.new(self.key, DES3.MODE_CBC, self.iv)
        data=cipher_encrypt.encrypt(data)
        return data

    def decrypt(self, data):
        cipher_decrypt=DES3.new(self.key, DES3.MODE_CBC, self.iv)
        data=cipher_decrypt.decrypt(data)
        data=unpad(data, DES.block_size)
        return data


# Data to be encrypted
data=b"Secret Message"

# Key must be either 24 bytes long
key=get_random_bytes(24)

# Generate a random IV
iv=get_random_bytes(DES3.block_size)

d3_outer_cbc=DES3_OUTER_CBC_EDE(key[0:8], key[8:16], key[16:24], iv)

ciphertext=d3_outer_cbc.encrypt(data)
plaintext=d3_outer_cbc.decrypt(ciphertext)

print("Ciphertext:", ciphertext)
print("Plaintext:", plaintext)

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
        random_bits=get_random_bytes(block_size // 2)
        return random_bits + data

    def __remove_random_bits(self, data, block_size):
        return data[block_size // 2:]

    def encrypt(self, data):

        # Padding the data to be a multiple of the block size
        data=pad(data, DES.block_size)

        # Encrypt with the first key
        cipher1=DES.new(self.key1, DES.MODE_ECB)
        data=cipher1.encrypt(data)

        # Add random bits between first and second encryption
        data=self.__add_random_bits(data, DES.block_size)

        # Padding the data to be a multiple of the block size
        data=pad(data, DES.block_size)

        # Encrypt with the second key
        cipher2=DES.new(self.key2, DES.MODE_ECB)
        data=cipher2.encrypt(data)

        # Add random bits between second and third encryption
        data=self.__add_random_bits(data, DES.block_size)

        # Padd the data to be a multiple of the block size
        data=pad(data, DES.block_size)

        # Encrypt with the third key
        cipher3=DES.new(self.key3, DES.MODE_ECB)
        data=cipher3.encrypt(data)

        return data

    def decrypt(self, data):
        # Decrypt with the third key
        cipher3=DES.new(self.key3, DES.MODE_ECB)
        data=cipher3.decrypt(data)

        # Unpad the decrypted data
        data=unpad(data, DES.block_size)

        # Remove random bits between second and third encryption from the start of the data
        data=self.__remove_random_bits(
            data, DES.block_size)

        # Decrypt with the second key
        cipher2=DES.new(self.key2, DES.MODE_ECB)
        data=cipher2.decrypt(data)

        # Unpad the decrypted data
        data=unpad(data, DES.block_size)

        # Remove random bits between first and second encryption
        data=self.__remove_random_bits(
            data, DES.block_size)

        # Decrypt with the first key
        cipher1=DES.new(self.key1, DES.MODE_ECB)
        data=cipher1.decrypt(data)

        # Unpad the decrypted data
        data=unpad(data, DES.block_size)
        return data


# Keys must be 8 bytes long each
key=get_random_bytes(24)

# Data to be encrypted
data=b'Your data here'

d3_ecb_pad_ede=DES3_ECB_PAD_EDE(key[0:8], key[8:16], key[16:24])

ciphertext3=d3_ecb_pad_ede.encrypt(data)
final_data=d3_ecb_pad_ede.decrypt(ciphertext3)

print(f"Encrypted: {ciphertext3}")
print(f"Decrypted: {final_data}")
