// Autores
// Juan Avila 20090
// Manuel Archila 161250
// Diego Franco 20240

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <openssl/des.h>
#include <time.h>
#include <stdlib.h>

#define BLOCK_SIZE 8

// Función para ajustar la paridad de la llave
void adjust_key_parity(uint64_t *key) { // Ajustar la paridad de la llave 
    uint64_t adjusted_key = 0;
    for (int i = 0; i < 8; ++i) {
        *key <<= 1;
        adjusted_key += (*key & (0xFEULL << (i * 8)));
    }
    DES_set_odd_parity((DES_cblock *)&adjusted_key);
    *key = adjusted_key;
}

// Función para encriptar un mensaje
void encrypt_message(uint64_t key, unsigned char *plaintext, unsigned char *ciphertext, int length) {
    adjust_key_parity(&key); // Ajustar la paridad de la llave antes de usarla
    DES_key_schedule schedule;
    DES_set_key_unchecked((const_DES_cblock *)&key, &schedule);
    for (int i = 0; i < length; i += BLOCK_SIZE) { // Encriptar el mensaje por bloques de 8 bytes
        DES_ecb_encrypt(plaintext + i, ciphertext + i, &schedule, DES_ENCRYPT);
    }
}

// Función para desencriptar un mensaje
void decrypt_message(uint64_t key, unsigned char *ciphertext, unsigned char *decryptedtext, int length) {
    adjust_key_parity(&key); // Ajustar la paridad de la llave antes de usarla
    DES_key_schedule schedule;
    DES_set_key_unchecked((const_DES_cblock *)&key, &schedule);
    for (int i = 0; i < length; i += BLOCK_SIZE) { // Desencriptar el mensaje por bloques de 8 bytes
        DES_ecb_encrypt(ciphertext + i, decryptedtext + i, &schedule, DES_DECRYPT);
    }
}

// Función para probar una llave y determinar si es la correcta
int tryKey(uint64_t key, unsigned char *ciph, int len, char *search) {
    unsigned char temp[len+1];
    memcpy(temp, ciph, len); // Copiar el mensaje cifrado en un arreglo temporal
    decrypt_message(key, temp, temp, len);// Desencriptar el mensaje con la llave
    temp[len] = 0;
    return strstr((char *)temp, search) != NULL;
}

int main() {
    char *plaintext = "Esta es una prueba del proyecto 2";
    int length = strlen(plaintext);

    // Determinar la longitud del fragmento como el 60% del plaintext (al menos 5 caracteres)
    int fragmentLength = length * 0.6;
    if (fragmentLength < 5) fragmentLength = 5;

    // Establecer una posición inicial aleatoria dentro del rango válido
    srand(time(NULL));
    int startPos = rand() % (length - fragmentLength + 1);

    char search[fragmentLength + 1];
    strncpy(search, plaintext + startPos, fragmentLength);
    search[fragmentLength] = '\0';

    printf("Fragmento extraído para búsqueda: %s\n", search);

    unsigned char ciphertext[length];
    uint64_t upper = (1L << 56); // límite superior para las llaves DES 2^56

    clock_t start, end;
    double cpu_time_used;
    start = clock();

    uint64_t key = 123556; // Llave inicial
    encrypt_message(key, (unsigned char *)plaintext, ciphertext, length);

    uint64_t found = 0; 
    for (uint64_t i = 0; i < upper; i++) { // Metodo de fuerza bruta
        if (tryKey(i, ciphertext, length, search)) { 
            found = i;
            break;
        }
    }

    end = clock();
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;

    unsigned char decrypted[length+1];
    decrypt_message(found, ciphertext, decrypted, length);
    decrypted[length] = 0;

    printf("Llave encontrada: %llu\n", found);
    printf("Texto desencriptado: %s\n", decrypted);
    printf("Tiempo usado: %f segundos\n", cpu_time_used);

    return 0;
}
