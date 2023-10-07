#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

void decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if(1 != EVP_DecryptInit_ex(ctx, EVP_des_ecb(), NULL, key, NULL)) handleErrors();

    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) handleErrors();
    plaintext_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
}

int tryKey(unsigned char *key, unsigned char *ciphertext, int ciphertext_len) {
    unsigned char decryptedtext[128];
    decrypt(ciphertext, ciphertext_len, key, decryptedtext);
    decryptedtext[ciphertext_len] = '\0';  // Null-terminate the result
    return strstr((char*)decryptedtext, " the ") != NULL;
}

int main(void) {
    unsigned char ciphertext[] = {0x6c, 0xf5, 0x41, 0x3f, 0x7d, 0xc8, 0x96, 0x42};
    int ciphertext_len = 8;
    unsigned char key[8];

    for (long i = 0; i < (1L << 56); ++i) {
        memcpy(key, &i, 8);  // Assuming the key is in a suitable format
        if (tryKey(key, ciphertext, ciphertext_len)) {
            printf("Found key: %ld\n", i);
            break;
        }
    }

    return 0;
}
