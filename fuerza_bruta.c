#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <openssl/des.h>
#include <time.h>

void encrypt_message(uint64_t key, unsigned char *plaintext, unsigned char *ciphertext) {
    DES_key_schedule schedule;
    DES_set_key_unchecked((const_DES_cblock *)&key, &schedule);  
    DES_ecb_encrypt(plaintext, ciphertext, &schedule, DES_ENCRYPT);
}

void decrypt_message(uint64_t key, unsigned char *ciphertext, unsigned char *decryptedtext) {
    DES_key_schedule schedule;
    DES_set_key_unchecked((const_DES_cblock *)&key, &schedule);  
    DES_ecb_encrypt(ciphertext, decryptedtext, &schedule, DES_DECRYPT);
}

void brute_force_search(const_DES_cblock ciphertext_target, const unsigned char *original_plaintext) {
    for (uint64_t key_num = 0; key_num < 0xFFFFFFFFFFFFFF; key_num++) {
        unsigned char decrypted[8];
        decrypt_message(key_num, ciphertext_target, decrypted);
        if (memcmp(decrypted, original_plaintext, 8) == 0) {
            printf("Llave encontrada: %llu\n", key_num);
            printf("Texto desencriptado: %s\n", decrypted);
            return;
        }
    }
}

int main() {
    unsigned char plaintext[8] = "HelloDes";
    unsigned char ciphertext[8];
    uint64_t key = 123456;

    encrypt_message(key, plaintext, ciphertext);
 
    clock_t start, end;
    double cpu_time_used;

    start = clock();
    brute_force_search(ciphertext, plaintext);
    end = clock();
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;

    printf("Tiempo usado: %f segundos\n", cpu_time_used);

    return 0;
}
