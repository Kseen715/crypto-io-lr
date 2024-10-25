from hashlib import sha256
import time
import os

from Crypto.Random import get_random_bytes
import colorama

import cbk


def generate_fake_file(filename, size):
    with open(filename, 'wb') as f:
        f.write(get_random_bytes(size))


if __name__ == '__main__':
    if not os.path.exists('temp'):
        os.makedirs('temp')
        print('Directory temp created')

    size_range = range(1, 11)
    test_iterations = 3

    # generate files from 1 MB to 100 MB with 1 MB step
    for i in size_range:
        if not os.path.exists(f'temp/file_{i}.bin'):
            generate_fake_file(f'temp/file_{i}.bin', i * 1024 * 1024)
            print(
                f'{colorama.Fore.GREEN}File temp/file_{i}.bin created{colorama.Style.RESET_ALL}')

    # with every method from cbk.py, encrypt and decrypt every file, measure time and write it to a csv file. Compate file's hash. Run all test 3 times.

    # generate keys
    key1, key2, key3 = cbk.generate_keys()

    # generate iv
    iv = cbk.generate_iv()

    modes = ["ecb_ede",
             "inner_cbc_ede",
             "outer_cbc_ede",
             "ecb_pad_ede"]

    with open(f'temp/test.csv', 'w') as f:
        f.write('method,iteration,file_size,time\n')
        for mode in modes:
            for j in size_range:
                for i in range(0, test_iterations):
                    input_file = f'temp/file_{j}.bin'
                    encrypted_file = f'temp/encrypted_{j}.bin'
                    decrypted_file = f'temp/decrypted_{j}.bin'

                    print(
                        f'{colorama.Fore.YELLOW}Method: {
                            mode}, File size: {
                            j} MB, Test {
                            i+1}/{test_iterations}{
                            colorama.Style.RESET_ALL}')

                    start = time.time()
                    cbk.encrypt_file(
                        input_file, encrypted_file, mode, key1, key2, key3, iv)
                    end = time.time()

                    start = time.time()
                    cbk.decrypt_file(
                        encrypted_file, decrypted_file, mode, key1, key2, key3, iv)
                    end = time.time()

                    f.write(f'{mode},{i+1},{j},{end-start}\n')
                    print(
                        f'{colorama.Fore.GREEN}File encrypted and decrypted{colorama.Style.RESET_ALL}. {colorama.Fore.GREEN}Time: {end-start}{colorama.Style.RESET_ALL}')
