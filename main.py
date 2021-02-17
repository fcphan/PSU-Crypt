import psu_crypt
import constants
import helpers
from sys import argv


def main(argv):
    # Read inputs
    if (len(argv) != 5) and (len(argv) != 6):
        print(
            f'Error: Incorrect number of arguments. Supplied {len(argv)} arguments. Using base case.')
        for a in argv:
            print(a)
        print("Compile using the following:")
        print(constants.color.BOLD +
              "python3 main.py <mode> <input> <key> <output> <padding>" + constants.color.END)
        print("\t<mode>: 'encrypt' or 'decrypt'")
        print("\t<input>: File to encrypt or decrypt")
        print("\t<key>: Key used for encryption and decryption")
        print("\t<output>: Output file to write results to.")
        print(
            "\t<padding>: padding result given when encrypting (only used for decryption)\n")
        helpers.base_case()
    else:
        # Set variables from command line arguments
        if argv[1] == 'encrypt':
            mode = argv[1]
        elif argv[1] == 'decrypt':
            mode = argv[1]
            padding = argv[5]   # Grab padding amount
        else:
            raise Exception(
                "Expected 'encrypt' or 'decrypt'. Instead got: " + argv[1])
        input_file = argv[2]
        key_file = argv[3]
        output_file = argv[4]

        # Open input file and read in input
        try:
            f = open(input_file, mode='r')
            input_text = f.read()
            f.close()
        except:
            print(
                'Error: Could not find ' + constants.color.GREEN + f'{input_file}' + constants.color.END + ' or file has invalid characters used.')
        # Open key file and get key value
        try:
            f = open(key_file, mode='r')
            input_key = f.read()
            f.close()
            # Key is read in as a string, so convert it into a base 16 integer
            input_key = int(input_key, base=16)
            # Verify key size
            if (len(int.to_bytes(input_key, 8, 'big').hex()) != 16):
                raise Exception(
                    "Error: Invalid key length. Please change key to valid length.")
        except:
            print(
                'Error: Could not find ' + constants.color.GREEN + f'{key_file}' + constants.color.END + ' or file has invalid characters used.')
            input_key = 0xabcdef0123456789
            print(
                f'Using base case key: {int.to_bytes(input_key, 8, "big").hex()}')

        if mode == 'encrypt':
            # Encryption
            cipher, pad = psu_crypt.encrypt(input_text, input_key)
            try:
                # Clear output file and write in new results
                f = open(output_file, mode='w').close()
                f = open(output_file, mode='a')
                for i in range(len(cipher)):
                    f.write(f'0x{int.to_bytes(cipher[i], 8, "big").hex()}\n')
                f.close()

                helpers.display(mode, input_text, input_key,
                                output_file, cipher, pad)
            except:
                print(f'Error: Failed to find {output_file}.')
        if mode == 'decrypt':
            # Decryption
            cipher_blocks = []  # Empty list to store ciphertext blocks
            # Read in ciphertext blocks
            try:
                with open(input_file, mode='r') as cipher:
                    for block in cipher:
                        cipher_blocks.append(int(block[:-1], 16))
            except:
                print(f'Error: Failed to find {input_file}.')

            plain = psu_crypt.decrypt(cipher_blocks, input_key, padding)
            # print(f'Plaintext: {plain}')
            try:
                # Clear output file and write in new results
                f = open(output_file, mode='w').close()
                f = open(output_file, mode='a')
                f.write(plain)
                f.close()
                helpers.display(mode, cipher_blocks, input_key,
                                output_file, plain, padding)
            except:
                print(f'Error: Failed to find {output_file}.')


if __name__ == '__main__':
    main(argv)
