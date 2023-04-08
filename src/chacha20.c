#include <stdint.h>
#include <string.h>
#include <stdio.h>

//#include "chacha20.h"
#include "simpleserial.h"


// check size of input bytes!
#define INPUT_SIZE 64
#define KEY_SIZE 32
#define NONCE_SIZE 12
#define COUNT_SIZE 4



static inline void u32t8le(uint32_t v, uint8_t p[4]) {
    p[0] = v & 0xff;
    p[1] = (v >> 8) & 0xff;
    p[2] = (v >> 16) & 0xff;
    p[3] = (v >> 24) & 0xff;
}

static inline uint32_t u8t32le(uint8_t p[4]) {
    uint32_t value = p[3];

    value = (value << 8) | p[2];
    value = (value << 8) | p[1];
    value = (value << 8) | p[0];

    return value;
}

static inline uint32_t rotl32(uint32_t x, int n) {
    // http://blog.regehr.org/archives/1063
    return x << n | (x >> (-n & 31));
}

// https://tools.ietf.org/html/rfc7539#section-2.1
static void chacha20_quarterround(uint32_t *x, int a, int b, int c, int d) {
    x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 16);
    x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 12);
    x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a],  8);
    x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c],  7);
}

static void chacha20_serialize(uint32_t in[16], uint8_t output[64]) {
    int i;
    for (i = 0; i < 16; i++) {
        u32t8le(in[i], output + (i << 2));
    }
}

static void chacha20_block(uint32_t in[16], uint8_t out[64], int num_rounds) {
    int i;
    uint32_t x[16];

    memcpy(x, in, sizeof(uint32_t) * 16);

    trigger_high();
    for (i = num_rounds; i > 0; i -= 2) {
	// column round
        chacha20_quarterround(x, 0, 4,  8, 12);
        chacha20_quarterround(x, 1, 5,  9, 13);
        chacha20_quarterround(x, 2, 6, 10, 14);
        chacha20_quarterround(x, 3, 7, 11, 15);

	// diagonal round
        chacha20_quarterround(x, 0, 5, 10, 15);
        chacha20_quarterround(x, 1, 6, 11, 12);
        chacha20_quarterround(x, 2, 7,  8, 13);
        chacha20_quarterround(x, 3, 4,  9, 14);
    }
    trigger_low();

    for (i = 0; i < 16; i++) {
        x[i] += in[i];
    }

    chacha20_serialize(x, out);
}

// https://tools.ietf.org/html/rfc7539#section-2.3
static void chacha20_init_state(uint32_t s[16], uint8_t key[32], uint32_t counter, uint8_t nonce[12]) {
    int i;

    // refer: https://dxr.mozilla.org/mozilla-beta/source/security/nss/lib/freebl/chacha20.c => not working
    // => see https://chromium.googlesource.com/chromium/deps/nss/+/50796110f60d034dfab3d8876f62d715f31aaa9f/nss/lib/freebl/chacha20/chacha20.c
    // convert magic number to string: "expand 32-byte k"
    s[0] = 0x61707865;
    s[1] = 0x3320646e;
    s[2] = 0x79622d32;
    s[3] = 0x6b206574;

    for (i = 0; i < 8; i++) {
        s[4 + i] = u8t32le(key + i * 4);
    }

    s[12] = counter;

    for (i = 0; i < 3; i++) {
        s[13 + i] = u8t32le(nonce + i * 4);
    }
}

void ChaCha20XOR(uint8_t key[32], uint32_t counter, uint8_t nonce[12], uint8_t *in, uint8_t *out, int inlen) {
    int i, j;

    uint32_t s[16];
    uint8_t block[64];

    chacha20_init_state(s, key, counter, nonce);

    for (i = 0; i < inlen; i += 64) {
        chacha20_block(s, block, 20);
        s[12]++;

        for (j = i; j < i + 64; j++) {
            if (j >= inlen) {
                break;
            }
            out[j] = in[j] ^ block[j - i];
        }
    }
}

uint8_t set_nonce(uint8_t* nc, uint8_t len){

    // size of nonce must be 12 bytes
    if (len != NONCE_SIZE+COUNT_SIZE) return 1;

    uint8_t encrypt[INPUT_SIZE];

    // key size 256 bit (32 bytes)
    uint8_t key[KEY_SIZE] = {
            0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b,
            0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13,
            0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f
    };

    // 12 bytes initial vector => 96 bit (in original 64 bit, but see: https://datatracker.ietf.org/doc/html/rfc7539#section-2.3)
    // => to be set in the attack scenario
    /*uint8_t nonce[NONCE_SIZE] = {
            nc[0], nc[1], nc[2], nc[3],
            nc[4], nc[5], nc[6], nc[7],
            nc[8], nc[9], nc[10], nc[11]
    };*/
    uint8_t nonce[NONCE_SIZE] = {
            nc[4], nc[5], nc[6], nc[7],
            nc[8], nc[9], nc[10], nc[11],
            nc[12], nc[13], nc[14], nc[15]
    };

    // 4 bytes counter
    // use function to get uint32_t LE counter
    /*uint8_t count_arr[COUNT_SIZE] = {
            nc[12], nc[13], nc[14], nc[15]
    };
    uint32_t counter = u8t32le(count_arr); */
    // conversion from uint8_t to uint32_t with shifting => BE?
    // https://forum.arduino.cc/t/convert-4-uint8_t-into-one-uint32_t/577243
    //uint32_t counter = nc[12] | (nc[13] << 8) | (nc[14] << 16) | (nc[15] << 24);
    uint32_t counter = nc[0] | (nc[1] << 8) | (nc[2] << 16) | (nc[3] << 24);

    // Hello from Chipwhispererer, I'm only here to get encrypted and yo(u?)
    uint8_t input[INPUT_SIZE] = {
            0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x66, 0x72,
            0x6f, 0x6d, 0x20, 0x43, 0x68, 0x69, 0x70, 0x77,
            0x68, 0x69, 0x73, 0x70, 0x65, 0x72, 0x65, 0x72,
            0x65, 0x72, 0x2c, 0x20, 0x49, 0x6d, 0x20, 0x6f,
            0x6e, 0x6c, 0x79, 0x20, 0x68, 0x65, 0x72, 0x65,
            0x20, 0x74, 0x6f, 0x20, 0x67, 0x65, 0x74, 0x20,
            0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65,
            0x64, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x79, 0x6f,
            //0x75, 0x3f
    };

    /* // Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it
    uint8_t input[INPUT_SIZE] = {
            0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
            0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
            0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
            0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
            0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
            0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
            0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
            0x74, 0x2e
    };
    */

    // encrypt
    ChaCha20XOR(key, counter, nonce, input, encrypt, INPUT_SIZE);

    // put encrypted/decrypted to simple serial
    simpleserial_put('r', INPUT_SIZE, encrypt);
    
    return 0;
}


int main(void) {

    platform_init();
    init_uart();
    trigger_setup();

    simpleserial_init();
    // 12 Bytes for nonce, 4 Bytes for counter
    simpleserial_addcmd('p', 16, set_nonce);

    while(1)
        simpleserial_get();

    return 0;
}