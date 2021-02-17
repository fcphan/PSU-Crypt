import constants

# Rotate bytes to the left or right


def rotate_bits(key, length, direction):
    # Rotate left
    if (direction == constants.LEFT):
        # Drop the right bit
        left_trunc = (2**length) - 2
        # Shift left, then drop the right bit
        reg = ((key << 1) & left_trunc)
        # Shift to catch the left bit to put on the righthand bit slot
        overflow = key >> (length - 1)

    # Rotate right
    if (direction == constants.RIGHT):
        # Drop the left bit
        right_trunc = 2**(length - 1)
        # Shift right, then drop the left bit
        reg = key >> 1
        # Shift to catch the right bit to put on the lefthand bit slot
        overflow = (key << (length - 1)) & right_trunc

    # Bitwise OR to append the overflow bit to the dropped bit position
    return (reg | overflow)

# Split hex into 4 pieces


def split(arg):
    ret = []
    ret.append((arg >> 48) & 0xFFFF)    # Grab first four hex values
    ret.append((arg >> 32) & 0xFFFF)    # Grab second four hex values
    ret.append((arg >> 16) & 0xFFFF)    # Grab third four hex values
    ret.append((arg >> 0) & 0xFFFF)    # Grab fourth four hex values
    return ret

# Base Case - used when incorrect input is given


def base_case():
    print(constants.color.BOLD +
          "------------------Beginning base case------------------" + constants.color.END)
    test_key = 0xabcdef0123456789
    test_plain = 0x0123456789abcdef
    print(
        f'Test Inputs:\n Key\t\t{int.to_bytes(test_key, 8, "big").hex()}' +
        f'\n Plaintext\t{int.to_bytes(test_plain, 8, "big").hex()}\n')
    cipher = psu_crypt.block_encryption(test_plain, test_key)
    print(f'Ciphertext:\t{int.to_bytes(cipher, 8, "big").hex()}')
    plain = psu_crypt.block_decryption(cipher, test_key)
    print(f'Plaintext:\t{int.to_bytes(plain, 8, "big").hex()}')
    print(constants.color.BOLD +
          "------------------Finishing base case------------------\n" + constants.color.END)


def display(mode, input, key, output, result, padding):
    # Print all ciphertext blocks
    def list_blocks(block_list):
        for block in block_list:
            print(f'\t\t{int.to_bytes(block, 8, "big").hex()}')
    # Set flag
    if mode == 'encrypt':
        flag = 'encryption'
    elif mode == 'decrypt':
        flag = 'decryption'
    else:
        raise Exception(
            "Error: Invalid mode. Expected 'encrypt' or 'decrypt', instead got: " + mode)
    print(constants.color.BOLD +
          f"------------------Beginning {flag}------------------" + constants.color.END)
    # Display input values based on flag
    print('Inputs:')
    if mode == 'encrypt':
        print(f'\tText:\t{input}')
    else:
        print("\tBlocks:")
        list_blocks(input)
        print(f'\tPad:\t{padding}')
    print(f'\tKey:\t{int.to_bytes(key, 8, "big").hex()}')
    # Display results and location they are written to
    print('\nOutput(s):')
    if mode == 'decrypt':
        print(f'\tText:\t{result}')
    else:
        print("\tBlocks:")
        list_blocks(result)
        print(f'\tPad:\t{padding}')
    print(f'\nResult written to {output}.')
    print(constants.color.BOLD +
          f"------------------Completed {flag}------------------" + constants.color.END)
