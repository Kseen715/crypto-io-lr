import sys
import os
import argparse

def bits_diff(a, b):
    return bin(a ^ b).count('1')

def print_bits(a):
    print(f'{a:08b}', end='')

def print_bits_array(arr):
    for a in arr:
        print_bits(a)

def changed_bits(file1, file2, chunk_size, limit):
    with open(file1, 'rb') as f1, open(file2, 'rb') as f2:
        readed = 0
        while readed < limit:
            chunk1 = f1.read(chunk_size)
            chunk2 = f2.read(chunk_size)
            # print bits
            # print_bits_array(chunk1)
            # print()
            # print_bits_array(chunk2)
            # print()

            if not chunk1 or not chunk2:
                break
            for a, b in zip(chunk1, chunk2):
                readed += chunk_size
                yield bits_diff(a, b)

def main():
    parser = argparse.ArgumentParser(description='Calculate count of bits different between two files')

    parser.add_argument('file1', help='first file')
    parser.add_argument('file2', help='second file')
    # optional argument
    parser.add_argument('--limit', type=int, default=4096, help='limit of comparison size in bytes')
    parser.add_argument('--log-file', type=str, default=None, help='log file')

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

    if args.limit <= 0:
        file_size = min(os.path.getsize(args.file1), os.path.getsize(args.file2))
        args.limit = file_size

    # print(f'Limit: {args.limit} bytes')
    # if chunk size > args.limit, then chunk size = args.limit
    # read only args.limit bytes of file
    for i in range (1, args.limit):
        chunk_size = 1024
        if chunk_size > i:
            chunk_size = i
        
        readed = 0
        total = 0
        changes = list(changed_bits(args.file1, args.file2, chunk_size, i))
        # print(changes)
        for bits in changes:
            # print(f'{bits}')
            total += bits
            readed += chunk_size
            # if readed >= args.limit:
            #     break
        if log_file_hand is not None:
            log_file_hand.write(f'{i},{total}\n')

    print(f'{total}')
    if log_file_hand is not None:
        log_file_hand.close()


if __name__ == '__main__':
    main()