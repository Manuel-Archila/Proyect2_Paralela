#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/des.h>

void decrypt(DES_cblock key, char *ciph, int len) {
    DES_key_schedule ks;
    DES_set_key_unchecked(&key, &ks);
    DES_ecb_encrypt((DES_cblock *)ciph, (DES_cblock *)ciph, &ks, DES_DECRYPT);
}

void encrypt(DES_cblock key, char *ciph, int len) {
    DES_key_schedule ks;
    DES_set_key_unchecked(&key, &ks);
    DES_ecb_encrypt((DES_cblock *)ciph, (DES_cblock *)ciph, &ks, DES_ENCRYPT);
}

char search[] = " the ";

int tryKey(DES_cblock key, char *ciph, int len) {
    char temp[len + 1];
    memcpy(temp, ciph, len);
    temp[len] = 0;
    decrypt(key, temp, len);
    return strstr((char *)temp, search) != NULL;
}

unsigned char cipher[] = {108, 245, 65, 63, 125, 200, 150, 66, 17, 170, 207, 170, 34, 31, 70, 215, 0};

int main() {
    long upper = (1L << 56); // upper bound DES keys 2^56
    int ciphlen = strlen((char *)cipher);

    DES_cblock found;
    memset(found, 0, sizeof(DES_cblock));

    for (long i = 0; i < upper && memcmp(found, "\0\0\0\0\0\0\0\0", 8) == 0; ++i) {
        DES_cblock key;
        *(long *)key = i; // convertir el long en un bloque DES
        if (tryKey(key, (char *)cipher, ciphlen)) {
            memcpy(found, key, sizeof(DES_cblock));
            break;
        }
    }

    decrypt(found, (char *)cipher, ciphlen);
    printf("%s %s\n", found, cipher);

    return 0;
}
