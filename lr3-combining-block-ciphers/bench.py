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

    size_range = range(1, 102, 10)
    test_iterations = 3
    step = (max(size_range) - min(size_range))/(len(size_range)-1)
    print(f'Size range: {list(size_range)}')
    print(f'Step: {step}')
    # generate files from 1 MB to 100 MB with 1 MB step
    for i in size_range:
        if not os.path.exists(f'temp/file_{i}.bin'):
            generate_fake_file(f'temp/file_{i}.bin', i * 1024 * 1024)
            print(
                f'{colorama.Fore.GREEN}File temp/file_{i}.bin '
                + f'created{colorama.Style.RESET_ALL}')

    # with every method from cbk.py, encrypt and decrypt every file, measure
    # time and write it to a csv file. Compate file's hash.
    # Run all test 3 times.

    # generate keys
    key1, key2, key3 = cbk.generate_keys()

    # generate iv
    iv = cbk.generate_iv()

    modes = ["ecb_ede",
             "native_ede",
             "inner_cbc_ede",
             "outer_cbc_ede",
             "ecb_pad_ede"]

    mod_count = len(modes)

    total_iterations = mod_count * \
        (len(size_range)) * test_iterations
    total_iterations = int(total_iterations)
    total_digits = len(str(int(total_iterations)))
    with open(f'temp/test.csv', 'w') as f:
        f.write('method,iteration,file_size,time\n')
        for mode in modes:
            for j in size_range:
                input_file = f'temp/file_{j}.bin'
                with open(input_file, "rb") as fd:
                    data = fd.read()
                for i in range(0, test_iterations):
                    # encrypted_file = f'temp/encrypted_{j}.bin'
                    # decrypted_file = f'temp/decrypted_{j}.bin'

                    # {current mode num}/{total mod num}
                    # .{current size}/{total size}
                    # .{current test num}/{total test num}
                    # prefix_str = str(modes.index(mode) + 1) + '/'
                    # + str(mod_count) + '.' + str(j) + '/'
                    # + str(size_range[-1]) + '.' + str(i + 1) + '/'
                    # + str(test_iterations)
                    current_iteration = modes.index(mode) \
                        * (len(size_range)) \
                        * test_iterations + (j/step) \
                        * test_iterations + i + 1
                    current_iteration = int(current_iteration)

                    print(
                        f'{colorama.Fore.YELLOW}'
                        + f'{current_iteration:{total_digits}d}/'
                        + f'{total_iterations:{total_digits}d} '
                        + f'Method: {mode}, '
                        + f'File size: {j} MB, '
                        + f'Test {i+1}{colorama.Style.RESET_ALL}'
                    )

                    start = time.time()
                    if mode == "ecb_ede":
                        cipher = cbk.DES3_ECB_EDE(key1, key2, key3)
                    elif mode == "native_ede":
                        cipher = cbk.DES3_NATIVE_EDE(key1, key2, key3)
                    elif mode == "inner_cbc_ede":
                        cipher = cbk.DES3_INNER_CBC_EDE(key1, key2, key3, iv)
                    elif mode == "outer_cbc_ede":
                        cipher = cbk.DES3_OUTER_CBC_EDE(key1, key2, key3, iv)
                    elif mode == "ecb_pad_ede":
                        cipher = cbk.DES3_ECB_PAD_EDE(key1, key2, key3)
                    else:
                        raise ValueError(f"Invalid mode: {mode}")
                    ciphertext = cipher.encrypt(data)
                    end = time.time()

                    start = time.time()
                    if mode == "ecb_ede":
                        cipher = cbk.DES3_ECB_EDE(key1, key2, key3)
                    elif mode == "native_ede":
                        cipher = cbk.DES3_NATIVE_EDE(key1, key2, key3)
                    elif mode == "inner_cbc_ede":
                        cipher = cbk.DES3_INNER_CBC_EDE(key1, key2, key3, iv)
                    elif mode == "outer_cbc_ede":
                        cipher = cbk.DES3_OUTER_CBC_EDE(key1, key2, key3, iv)
                    elif mode == "ecb_pad_ede":
                        cipher = cbk.DES3_ECB_PAD_EDE(key1, key2, key3)
                    else:
                        raise ValueError(f"Invalid mode: {mode}")
                    plaintext = cipher.decrypt(ciphertext)
                    end = time.time()

                    f.write(f'{mode},{i+1},{j},{end-start}\n')
                    print(
                        f'{colorama.Fore.GREEN}File encrypted and decrypted'
                        + f'{colorama.Style.RESET_ALL}. '
                        + f'{colorama.Fore.GREEN}Time: '
                        + f'{end-start}{colorama.Style.RESET_ALL}')
