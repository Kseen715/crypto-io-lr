import sys
import os
import argparse


def bits_diff(a, b):
    if not isinstance(a, bytes):
        if isinstance(a, int):
            a = bytearray([a])
    if not isinstance(a, bytes):
        if isinstance(a, int):
            b = bytearray([b])
    bits1 = ''.join([f'{a:08b}' for a in a])
    bits2 = ''.join([f'{a:08b}' for a in b])
    len1 = len(bits1)
    len2 = len(bits2)
    max_len = max(len(bits1), len(bits2))
    bits1 = bits1.ljust(max_len, '0')
    bits2 = bits2.ljust(max_len, '0')
    output_str = ""
    for i in range(max_len):
        if i < len1 and i < len2:
            if bits1[i] == bits2[i]:
                output_str += '0'
            else:
                output_str += '1'
        else:
            output_str += '1'
    return output_str.count('1'), output_str


def print_bits(a):
    print(f'{a:08b}', end='')


def print_bits_array(arr):
    for a in arr:
        print_bits(a)


def print_bit_diff(arr1, arr2):
    diffstr = bits_diff(arr1, arr2)[1]
    out_str = ""
    real_len = min(len(arr1), len(arr2)) * 8
    for i in range(len(diffstr)):
        if i < real_len:
            if diffstr[i] == '1':
                out_str += "\033[38;2;255;16;16m" + '1'
            else:
                out_str += "\033[38;2;66;166;66m" + '0'
        else:
            out_str += "\033[38;2;228;128;128m" + '1'
    out_str += "\033[0m"
    print(out_str)


def main():
    parser = argparse.ArgumentParser(
        description='Calculate count of bits different between two files')

    parser.add_argument('file1', help='first file')
    parser.add_argument('file2', help='second file')
    # optional argument
    parser.add_argument('--limit', type=int, default=4096,
                        help='limit of comparison size in bytes')
    parser.add_argument('--log-file', type=str, default=None, help='log file')
    parser.add_argument('--verbose', action='store_true',
                        help='print bit representation of files')

    args = parser.parse_args()

    log_file_hand = None
    if args.log_file is not None:
        log_file_hand = open(args.log_file, 'w')

    if not os.path.exists(args.file1):
        print(f'File {args.file1} does not exist')
        sys.exit(1)

    if not os.path.exists(args.file2):
        print(f'File {args.file2} does not exist')
        sys.exit(1)

    if args.limit <= 0 or args.limit == None:
        file_size = min(
            os.path.getsize(args.file1),
            os.path.getsize(args.file2))
        args.limit = file_size

    with open(args.file1, 'rb') as f1, open(args.file2, 'rb') as f2:
        data1 = f1.read()
        data2 = f2.read()
        if args.verbose:
            print('src1:\t', end='')
            print_bits_array(data1)
            print()
            print('src2:\t', end='')
            print_bits_array(data2)
            print()
            print('diff:\t', end='')
            print_bit_diff(data1, data2)
            print(bits_diff(data1, data2))
        else:
            print(bits_diff(data1, data2)[0])


if __name__ == '__main__':
    main()
