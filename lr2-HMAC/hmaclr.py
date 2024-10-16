#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Python 3.12.6


import hmac
import os
import argparse
from hashlib import sha256
import getpass

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import tqdm
import pyautogui
from PIL import ImageGrab
import colorama as clr


def get_mouse_pixel_data():
    # Get the current mouse position
    x, y = pyautogui.position()

    # Capture the screen at the mouse position
    screen = ImageGrab.grab(bbox=(x, y, x+1, y+1))

    # Get the RGB value of the pixel
    pixel = screen.load()
    r, g, b = pixel[0, 0]

    return x, y, r, g, b


def get_salt(byte_len) -> int:
    salt = 0
    bitlen = byte_len * 8
    prev_x, prev_y, prev_r, prev_g, prev_b = None, None, None, None, None
    print(f'{clr.Fore.LIGHTYELLOW_EX}Getting salt. {
        '\033[4m'}Move the mouse around the screen.{clr.Style.RESET_ALL}')
    # for _ in range((bitlen // 5) + 1):
    for _ in tqdm.tqdm(range((bitlen // 5) + 1), desc='Getting salt'):
        while True:
            x, y, r, g, b = get_mouse_pixel_data()
            if (x, y, r, g, b) != (prev_x, prev_y, prev_r, prev_g, prev_b):
                prev_x, prev_y, prev_r, prev_g, prev_b = x, y, r, g, b
                salt = (salt << 1) | (x & 0x01)
                salt = (salt << 1) | (y & 0x01)
                salt = (salt << 1) | (r & 0x01)
                salt = (salt << 1) | (g & 0x01)
                salt = (salt << 1) | (b & 0x01)
                # print last 5 bits in binary, with leading zeros
                # print(f'{salt & 0x1F:05b}', end='\r')
                bitlen -= 5
                break
    # cut the excessive bits
    salt = salt >> (bitlen * -1)
    return salt


def count_zeros_ones_binary(num, bytelength=32):
    zeros = 0
    ones = 0
    while num:
        if num & 1:
            ones += 1
        else:
            pass
        num >>= 1
    bitlen = bytelength * 8
    zeros = bitlen - ones
    return zeros, ones


def get_password_salted_hash(salt, password):
    # invert bits in password
    # repr every char in password as bytes, then invert bits in every byte
    password = int.from_bytes(
        bytes([(~char + 256) % 256 for char in password.encode('utf-8')]), 'big')
    # if password longer than 32 bytes, fold it recursively to 32 bytes using XOR
    while password.bit_length() > 256:
        password = (password >> 256) ^ (
            password & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)

    # add salt to password and hash
    salted_password = salt.to_bytes(32, 'big') + password.to_bytes(32, 'big')
    return sha256(salted_password).digest()


def get_iv(byte_len):
    return get_random_bytes(byte_len)


def get_hmac(key, data):
    return hmac.new(key, data, sha256).digest()


def cypher_file(file_path, passw, output_path=None):
    # [salt(32B)][HMAC(32B)][IV(16B)][cipher_text]
    assert os.path.exists(file_path), f'File {file_path} does not exist'
    assert os.path.isfile(file_path), f'{file_path} is not a file'
    assert output_path is not None, 'Output path is not provided'
    if os.path.exists(output_path):
        response = input(f'{clr.Fore.YELLOW}File {
                         output_path} already exists. Overwrite? [Y/n]{clr.Style.RESET_ALL}')
        if response.lower() != 'y' and response.lower() != '':
            return
    if not os.path.exists(os.path.dirname(output_path)):
        os.makedirs(os.path.dirname(output_path))
    salt = get_salt(32)
    print(salt)
    iv = get_iv(16)
    print("IV: ", iv)
    key = get_password_salted_hash(salt, passw)
    print(key)
    hmac = None
    with open(file_path, 'rb') as file:
        hmac = get_hmac(key, file.read())
    print(hmac)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    print(f'Encrypting file {file_path} to {output_path}...')
    with open(file_path, 'rb') as file:
        with open(output_path, 'wb') as enc_file:
            enc_file.write(salt.to_bytes(32, 'big'))
            enc_file.write(hmac)
            enc_file.write(iv)
            while chunk := file.read(16 * 1024):
                enc_file.write(cipher.encrypt(chunk))


def decypher_file(file_path, passw, output_path=None, check=True):
    # [salt(32B)][HMAC(32B)][IV(16B)][cipher_text]
    assert os.path.exists(file_path), f'File {file_path} does not exist'
    assert os.path.isfile(file_path), f'{file_path} is not a file'
    assert output_path is not None, 'Output path is not provided'
    if os.path.exists(output_path):
        response = input(f'{clr.Fore.YELLOW}File {
                         output_path} already exists. Overwrite? [Y/n]{clr.Style.RESET_ALL}')
        if response.lower() != 'y' and response.lower() != '':
            return
    if not os.path.exists(os.path.dirname(output_path)):
        os.makedirs(os.path.dirname(output_path))
    print(f'Decrypting file {file_path} to {output_path}...')
    checkres = None
    with open(file_path, 'rb') as file:
        salt = int.from_bytes(file.read(32), 'big')
        hmac = file.read(32)
        iv = file.read(16)
        key = get_password_salted_hash(salt, passw)
        cipher = AES.new(key, AES.MODE_CFB, iv)
        decrypted_data = b''
        while chunk := file.read(16 * 1024):
            decrypted_data += cipher.decrypt(chunk)
        checkres = get_hmac(key, decrypted_data)
        if hmac == checkres:
            with open(output_path, 'wb') as dec_file:
                dec_file.write(decrypted_data)
    if check:
        if hmac == checkres:
            print(f'HMAC is {clr.Fore.GREEN}correct{clr.Style.RESET_ALL}')
        else:
            print(f'HMAC is {clr.Fore.RED}incorrect{clr.Style.RESET_ALL}')


def main():
    parser = argparse.ArgumentParser(
        description='Encrypt/decrypt file with HMAC-AES-256-CFB')
    parser.add_argument('file', type=str, help='File to encrypt/decrypt')
    parser.add_argument('output', type=str, help='Output file')
    parser.add_argument('-d', '--decrypt',
                        action='store_true', help='Decrypt file')
    # do not check HMAC option
    parser.add_argument('--no-check', dest='check', action='store_false',
                        help='Do not check HMAC after decryption')

    args = parser.parse_args()

    # show help if no arguments provided
    if not vars(args) or not args.file or not args.output:
        parser.print_help()
        parser.exit()

    password = getpass.getpass(prompt=f'{clr.Fore.CYAN}Enter password: {
                               clr.Style.RESET_ALL}')
    if args.decrypt:
        decypher_file(args.file, password, args.output, args.check)
    else:
        cypher_file(args.file, password, args.output)


if __name__ == "__main__":
    main()
