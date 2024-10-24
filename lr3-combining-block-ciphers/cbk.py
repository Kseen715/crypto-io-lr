#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Python 3.12.6

import os
import argparse

from Crypto.Cipher import DES3
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


key = os.urandom(24)

# ✨ 3DES ECB -------------------------------------------------------------------
ciper = DES3.new(key, DES3.MODE_ECB)
data = b"Secret Message".ljust(16)  # Padding to block size

# Encrypt
ciphertext = ciper.encrypt(data)

# Decrypt
plaintext = ciper.decrypt(ciphertext).strip()

print("Ciphertext:", ciphertext)
print("Plaintext:", plaintext)

# ✨ 3DES Inner CBC -------------------------------------------------------------
# во внутреннем CBC сцепление блоков происходит на каждом из трех этапов 
# шифрования

def des_cbc_encrypt(key, iv, data):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return cipher.encrypt(data)

def des_cbc_decrypt(key, iv, data):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return cipher.decrypt(data)

# Keys and IVs for each DES operation
key1 = get_random_bytes(8)
key2 = get_random_bytes(8)
key3 = get_random_bytes(8)
iv = get_random_bytes(8)  # Single IV for inner CBC

# Data to encrypt
data = b"Secret Message".ljust(16)  # Padding to block size

# Encrypt with DES1
ciphertext1 = des_cbc_encrypt(key1, iv, data)

# Decrypt with DES2
ciphertext2 = des_cbc_decrypt(key2, iv, ciphertext1)

# Encrypt with DES3
ciphertext3 = des_cbc_encrypt(key3, iv, ciphertext2)

# Decrypt with DES3
plaintext2 = des_cbc_decrypt(key3, iv, ciphertext3)

# Encrypt with DES2
plaintext1 = des_cbc_encrypt(key2, iv, plaintext2)

# Decrypt with DES1
plaintext = des_cbc_decrypt(key1, iv, plaintext1).strip()

print("Ciphertext:", ciphertext3)
print("Plaintext:", plaintext)

# ✨ 3DES Outer CBC -------------------------------------------------------------
# во внешнем CBC сцепление работает так, как будто все три этапа шифрования
# являются одним

# Key must be either 16 or 24 bytes long
key = b'Sixteen byte key'

# Data to be encrypted
data = b"Secret Message"

# Generate a random IV
iv = get_random_bytes(DES3.block_size)

# Padding the data to be a multiple of the block size
padded_data = pad(data, DES3.block_size)

# Encrypt
cipher_encrypt = DES3.new(key, DES3.MODE_CBC, iv)
ciphertext = cipher_encrypt.encrypt(padded_data)

# Decrypt
cipher_decrypt = DES3.new(key, DES3.MODE_CBC, iv)
decrypted_padded_data = cipher_decrypt.decrypt(ciphertext)

# Unpadding the decrypted data
plaintext = unpad(decrypted_padded_data, DES3.block_size)

print("Ciphertext:", ciphertext)
print("Plaintext:", plaintext)

# ✨ 3DES with pad --------------------------------------------------------------
# In the 3DES with pad mode, between the first and second encryptions and 
# between the second and third encryptions, the text is supplemented with a 
# string of random bits half a block long. This ensures that the encryption 
# blocks overlap.

# В режиме 3DES with pad между первым и вторым, а также между вторым и третьим 
# шифрованиями текст дополняется строкой случайных битов длинной полблока. 
# Таким образом обеспечивается перекрытие блоков шифрования
def add_random_bits(data, block_size):
    random_bits = get_random_bytes(block_size // 2)
    return random_bits + data

# Keys must be 8 bytes long each
key1 = b'8byteke1'
key2 = b'8byteke2'
key3 = b'8byteke3'

# Data to be encrypted
data = b'Your data here'

# Padding the data to be a multiple of the block size
padded_data = pad(data, DES.block_size)

# Encrypt with the first key
cipher1 = DES.new(key1, DES.MODE_ECB)
ciphertext1 = cipher1.encrypt(padded_data)

# Add random bits between first and second encryption
ciphertext1 = add_random_bits(ciphertext1, DES.block_size)

# Padding the data to be a multiple of the block size
ciphertext1 = pad(ciphertext1, DES.block_size)

# Encrypt with the second key
cipher2 = DES.new(key2, DES.MODE_ECB)
ciphertext2 = cipher2.encrypt(ciphertext1)

# Add random bits between second and third encryption
ciphertext2 = add_random_bits(ciphertext2, DES.block_size)

# Padd the data to be a multiple of the block size
ciphertext2 = pad(ciphertext2, DES.block_size)

# Encrypt with the third key
cipher3 = DES.new(key3, DES.MODE_ECB)
ciphertext3 = cipher3.encrypt(ciphertext2)

# Decryption process
# Decrypt with the third key
decrypted_data1 = cipher3.decrypt(ciphertext3)

# Unpad the decrypted data
decrypted_data1 = unpad(decrypted_data1, DES.block_size)

# Remove random bits between second and third encryption from the start of the data
decrypted_data1 = decrypted_data1[DES.block_size // 2:]

# Decrypt with the second key
decrypted_data2 = cipher2.decrypt(decrypted_data1)

# Unpad the decrypted data
decrypted_data2 = unpad(decrypted_data2, DES.block_size)

# Remove random bits between first and second encryption
decrypted_data2 = decrypted_data2[DES.block_size // 2:]

# Decrypt with the first key
decrypted_data3 = cipher1.decrypt(decrypted_data2)

# Unpad the decrypted data
final_data = unpad(decrypted_data3, DES.block_size)

print(f"Encrypted: {ciphertext3}")
print(f"Decrypted: {final_data}")
