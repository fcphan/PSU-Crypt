import constants
import helpers


def encrypt(plaintext, key):
    # Add padding to make sure each block is of size 64
    padding = 64 - len(plaintext) % 64
    for p in range(padding):
        plaintext = plaintext + 'F'
    # Set up list objects to store plaintext blocks and encrypted blocks
    to_encrypt = []
    encrypted = []
    # Convert plaintext into plaintext blocks and store in list
    for i in range(len(plaintext) // 8):
        tmp = plaintext[i*8:(i+1)*8]
        tmp = tmp.encode('utf-8')
        tmp = int.from_bytes(tmp, "big")
        to_encrypt.append(tmp)
    # Encrypt each block
    for b in to_encrypt:
        encrypted.append(block_encryption(b, key))
    # Return encrypted blocks and how much padding was added
    return encrypted, padding


def block_encryption(pt_block, key):
    # Generate keystream
    keystream = get_keystream(key)
    # w0-w4 according to document
    word_split = helpers.split(pt_block)
    # k0-k4 according to document
    key_split = helpers.split(key)
    # r0-r3 according to dcoument
    r = [0] * 4
    # storage for undoing final swap
    y = [0] * 4
    # storage for ciphertext after whitening
    c = [0] * 4
    # Round counter
    round_number = 0
    # Whiten input
    for n in range(4):
        r[n] = word_split[n] ^ key_split[n]
    # 16 round F()
    for round in range(constants.ROUNDS):
        f0, f1 = F(r[0], r[1], keystream[round], round_number)
        tmp_r0 = r[0]
        tmp_r1 = r[1]
        r[0] = r[2] ^ f0
        r[1] = r[3] ^ f1
        r[2] = tmp_r0
        r[3] = tmp_r1
        round_number = round_number + 3
    # Undo final swap
    y[0] = r[2]
    y[1] = r[3]
    y[2] = r[0]
    y[3] = r[1]
    # Whiten output
    for n in range(4):
        c[n] = y[n] ^ key_split[n]
        # Shift right to allow the bytes to be concatenated, reduce shift amount in increments of 16
        c[n] = c[n] << (constants.KEYSIZE - (16 * (n + 1)))
    # Return encrypted blocks
    return c[0] | c[1] | c[2] | c[3]


def decrypt(ciphertext, key, padding):
    # Create list to store decrypted value
    decrypted = []
    # Decrypt each block in the ciphertext
    for c in ciphertext:
        block = block_decryption(c, key)
        tmp = int.to_bytes(block, length=8, byteorder='big')
        decrypted.append(tmp.decode('utf-8'))
    # Convert list into a string and return string (except the padding)
    decrypted = ''.join(decrypted)
    # Return decrypted text without padding
    return decrypted[:-int(padding)]


def block_decryption(ct_block, key):
    # Generate keystream
    keystream = get_keystream(key)
    # w0-w4 according to document
    word_split = helpers.split(ct_block)
    # k0-k4 according to document
    key_split = helpers.split(key)
    # r0-r3 according to dcoument
    r = [0] * 4
    # storage for undoing final swap
    y = [0] * 4
    # storage for ciphertext after whitening
    c = [0] * 4
    # Round counter - set to maximum
    round_number = 45
    # Whiten input
    for n in range(4):
        r[n] = word_split[n] ^ key_split[n]
    # 16 round F()
    for round in range(constants.ROUNDS):
        f0, f1 = F(r[0], r[1], keystream[15 - round], round_number)
        tmp_r0 = r[0]
        tmp_r1 = r[1]
        r[0] = r[2] ^ f0
        r[1] = r[3] ^ f1
        r[2] = tmp_r0
        r[3] = tmp_r1
        round_number = round_number - 3
    # Undo final swap
    y[0] = r[2]
    y[1] = r[3]
    y[2] = r[0]
    y[3] = r[1]
    # Whiten output
    for n in range(4):
        c[n] = y[n] ^ key_split[n]
        # Shift right to allow the bytes to be concatenated, reduce shift amount in increments of 16
        c[n] = c[n] << (constants.KEYSIZE - (16 * (n + 1)))
    # Return encrypted blocks
    return c[0] | c[1] | c[2] | c[3]


def F(r0, r1, keyrow, round):
    # Pass keys to g_permutation
    t0 = g_permutation(r0, keyrow, round)
    t1 = g_permutation(r1, keyrow, round + 1)

    # print('t')
    # print(int.to_bytes(t0, 8, "big").hex())
    # print(int.to_bytes(t1, 8, "big").hex())
    # print('\n')

    # Calculate f0
    key_left = keyrow[4 * (round + 2)]
    key_right = keyrow[4 * (round + 2) + 1]
    key_left = key_left << 8
    concat = key_left | key_right
    f0 = (t0 + (2 * t1) + concat) % 2**16
    # Calculate f1
    key_left = keyrow[4 * (round + 2) + 2]
    key_right = keyrow[4 * (round + 2) + 3]
    key_left = key_left << 8
    concat = key_left | key_right
    f1 = ((2 * t0) + t1 + concat) % 2**16

    # print('f')
    # print(int.to_bytes(f0, 8, "big").hex())
    # print(int.to_bytes(f1, 8, "big").hex())
    # print('\n')

    # Return f0 and f1
    return f0, f1


def g_permutation(w, keyrow, round):
    # Empty lists
    g = [0] * 6
    # High 8 bits of w
    g[0] = (w >> 8) & 0xFF
    # Low 8 bits of w
    g[1] = w & 0xFF

    for i in range(4):
        unroll = g[i + 1] ^ keyrow[4 * round + i]
        # Find row value
        left = (unroll >> 4) & 0xF
        # Find column value
        right = unroll & 0xF
        # XOR ftable with previous g output
        g[i + 2] = constants.f_table[left * 16 + right] ^ g[i]
    # Bit shift g4 to make room for concatenating g5
    g[4] = (g[4] << 8)
    return (g[4] | g[5])


def get_keystream(key):
    # Create an empty list with 16 rows
    keys = [[]] * 16
    # Counter used to swap sides
    counter = 0
    counter_trunc = 0
    # Set shift_key to be the initial key
    shift_key = key

    for i in range(192):
        # Rotate left first
        shift_key = helpers.rotate_bits(
            shift_key, constants.KEYSIZE, constants.LEFT)
        # Hold onto key to truncate and right shifts
        shift_trunc = shift_key
        # Right half of keyspace
        if counter < 12:
            # Number of times needed to truncate in order to drop two right most hex values
            for ct in range(counter_trunc):
                # Rotate 8 times to get next subkey
                for n in range(8):
                    shift_trunc = helpers.rotate_bits(
                        shift_trunc, constants.KEYSIZE, constants.RIGHT)
        else:
            # Rotate 32 times in order to get original subkeys
            for n in range(32):
                shift_trunc = helpers.rotate_bits(
                    shift_trunc, constants.KEYSIZE, constants.RIGHT)
            # Number of times needed to truncate in order to drop two right most hex values
            for ct in range(counter_trunc):
                # Rotate 8 times to get next subkey
                for n in range(8):
                    shift_trunc = helpers.rotate_bits(
                        shift_trunc, constants.KEYSIZE, constants.RIGHT)
        # Truncate excess in order to keep 32-bit subkeys
        excess_bits = shift_trunc & 0xFF
        # Add to keys list in row i
        keys[i // 16].append(excess_bits)
        # Increment number of shifts to reach next block
        counter_trunc = (counter_trunc + 1) % 4
        # Increment counter for swapping sides
        counter = (counter + 1) % 24
    return keys
