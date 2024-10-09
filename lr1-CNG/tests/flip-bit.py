import sys
import os
import argparse

def flip_n_bit(input_file, n, output_file):
    """
    Flip single bit in file at position n (bit numbering starts from 0)
    """
    with open(input_file, 'rb') as f:
        data = f.read()
    data = bytearray(data)
    
    byte_index = n // 8
    bit_index = n % 8
    
    data[byte_index] ^= (1 << bit_index)
    
    with open(output_file, 'wb') as f:
        f.write(data)

def main():
    parser = argparse.ArgumentParser(description='Flip n bits in file')

    parser.add_argument('input_file', help='input file')
    parser.add_argument('n', type=int, help='number of bit to flip')
    parser.add_argument('output_file', help='output file')

    args = parser.parse_args()

    if not os.path.exists(args.input_file):
        print(f'File {args.input_file} does not exist')
        sys.exit(1)

    flip_n_bit(args.input_file, args.n, args.output_file)

if __name__ == '__main__':
    main()