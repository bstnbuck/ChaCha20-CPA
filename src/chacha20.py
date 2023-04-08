"""
original source
https://github.com/schmxtz/CHACHA20-Python-implementation/blob/main/CHACHA20.py
"""

# hamming weight, pre-calculate
HW = [bin(n).count("1") for n in range(0, 64)]
hw_l = [0] * 64


# helper functions
def rotate_bits(s, offset):
    state_with_leading_zeros = '{:032b}'.format(s)
    return int(state_with_leading_zeros[offset:] + state_with_leading_zeros[:offset], 2)


def add_mod_2_pow32(left_summand, right_summand):
    return (left_summand + right_summand) % 2 ** 32


def bitwise_xor(left_bytes, right_bytes):
    return left_bytes ^ right_bytes


def chacha20_quarterround(s: list, a, b, c, d):
    s[a] = add_mod_2_pow32(s[a], s[b])

    s[d] = bitwise_xor(s[d], s[a])
    s[d] = rotate_bits(s[d], 16)

    s[c] = add_mod_2_pow32(s[c], s[d])
    s[b] = bitwise_xor(s[b], s[c])
    s[b] = rotate_bits(s[b], 12)

    s[a] = add_mod_2_pow32(s[a], s[b])
    s[d] = bitwise_xor(s[d], s[a])
    s[d] = rotate_bits(s[d], 8)

    s[c] = add_mod_2_pow32(s[c], s[d])
    s[b] = bitwise_xor(s[b], s[c])
    s[b] = rotate_bits(s[b], 7)


def chacha20_block(state):
    s = state.copy()
    for _ in range(10):
        # column rounds
        chacha20_quarterround(s, 0, 4, 8, 12)
        chacha20_quarterround(s, 1, 5, 9, 13)
        chacha20_quarterround(s, 2, 6, 10, 14)
        chacha20_quarterround(s, 3, 7, 11, 15)

        # diagonal rounds
        chacha20_quarterround(s, 0, 5, 10, 15)
        chacha20_quarterround(s, 1, 6, 11, 12)
        chacha20_quarterround(s, 2, 7, 8, 13)
        chacha20_quarterround(s, 3, 4, 9, 14)

    # modular additions
    for h in range(16):
        state[h] = add_mod_2_pow32(state[h], s[h])

    # alias ChaCha20 serialize
    result = bytes()
    for h in range(16):
        result += int.to_bytes(state[h], 4, 'little')
    return result


def ChaCha20XOR(state, input_text, count):
    input_text_length = len(input_text)
    k = chacha20_block(state)
    while len(k) < input_text_length:
        k += chacha20_block(state)
        count += 1
    return bytes(a ^ b for a, b in zip(k[:input_text_length], input_text))


def crypt(key, nonce, counter, inp):
    state = [0] * 16
    if len(key) != 32:
        raise ValueError('Invalid key length')
    if len(nonce) != 12:
        raise ValueError('Invalid nonce length')

    # Initialize constants
    state[0] = 0x61707865
    state[1] = 0x3320646e
    state[2] = 0x79622d32
    state[3] = 0x6b206574

    # Initialize key fields
    for i in range(8):
        state[4 + i] = int.from_bytes(key[i * 4: (i + 1) * 4], byteorder='little')

    # Initialize counter
    state[12] = int.from_bytes(counter, byteorder='little')

    # Initialize nonce
    for i in range(3):
        state[13 + i] = int.from_bytes(nonce[i * 4: (i + 1) * 4], byteorder='little')

    return ChaCha20XOR(state, inp, counter)

#########################################################################


if __name__ == "__main__":
    key = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
           0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
           0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
           0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f]

    inp = [0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x66, 0x72,
           0x6f, 0x6d, 0x20, 0x43, 0x68, 0x69, 0x70, 0x77,
           0x68, 0x69, 0x73, 0x70, 0x65, 0x72, 0x65, 0x72,
           0x65, 0x72, 0x2c, 0x20, 0x49, 0x6d, 0x20, 0x6f,
           0x6e, 0x6c, 0x79, 0x20, 0x68, 0x65, 0x72, 0x65,
           0x20, 0x74, 0x6f, 0x20, 0x67, 0x65, 0x74, 0x20,
           0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65,
           0x64, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x79, 0x6f]

    counter = [0x01, 0x00, 0x00, 0x00]

    nonce = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x10, 0x00, 0x00, 0x00, 0xaa]

    print("\nCiphertext encrypted:")
    ciphertext = crypt(key, nonce, counter, inp)
    for i, byte in enumerate(ciphertext):
        print(f'{byte:02x}', end=' ')
        if not (i % 16) and i != 0:
            print()

    print("\n\nCleartext decrypted:")
    cleartext = crypt(key, nonce, counter, ciphertext)
    for i, byte in enumerate(cleartext):
        print(f'{byte:02x}', end=' ')
        if not (i % 16) and i != 0:
            print()
