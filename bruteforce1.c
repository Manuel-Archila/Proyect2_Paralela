#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <mpi.h>
#include <openssl/des.h>
#include <time.h>
#include <stdlib.h>

#define BLOCK_SIZE 8

void adjust_key_parity(uint64_t *key) {
    uint64_t adjusted_key = 0;
    for (int i = 0; i < 8; ++i) {
        *key <<= 1;
        adjusted_key += (*key & (0xFEULL << (i * 8)));
    }
    DES_set_odd_parity((DES_cblock *)&adjusted_key);
    *key = adjusted_key;
}

void encrypt_message(uint64_t key, unsigned char *plaintext, unsigned char *ciphertext, int length) {
    adjust_key_parity(&key);
    DES_key_schedule schedule;
    DES_set_key_unchecked((const_DES_cblock *)&key, &schedule);
    for (int i = 0; i < length; i += BLOCK_SIZE) {
        DES_ecb_encrypt(plaintext + i, ciphertext + i, &schedule, DES_ENCRYPT);
    }
}

void decrypt_message(uint64_t key, unsigned char *ciphertext, unsigned char *decryptedtext, int length) {
    adjust_key_parity(&key);
    DES_key_schedule schedule;
    DES_set_key_unchecked((const_DES_cblock *)&key, &schedule);
    for (int i = 0; i < length; i += BLOCK_SIZE) {
        DES_ecb_encrypt(ciphertext + i, decryptedtext + i, &schedule, DES_DECRYPT);
    }
}

int tryKey(uint64_t key, unsigned char *ciph, int len, char *search) {
    unsigned char temp[len+1];
    memcpy(temp, ciph, len);
    decrypt_message(key, temp, temp, len);
    temp[len] = 0;
    return strstr((char *)temp, search) != NULL;
}

int main(int argc, char *argv[]) {

    // Leer archivo de texto 
    FILE *fp;
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    fp = fopen("entrada.txt", "r");
    if (fp == NULL)
        exit(EXIT_FAILURE);

    char *plaintext = line;
    while ((read = getline(&line, &len, fp)) != -1) {
        plaintext = line;
    }

    fclose(fp);
    printf("Texto recibido: %s\n", plaintext);

    uint64_t key = strtoull(argv[1], NULL, 10); // 10 indica base decimal
    printf("Key: %llu\n", key);


    int length = strlen(plaintext);

    unsigned char ciphertext[length];
    encrypt_message(key, (unsigned char *)plaintext, ciphertext, length);
    
    int N, id;
    long upper = (1L << 56); // límite superior para las llaves DES 2^56
    long mylower, myupper;
    MPI_Status st;
    MPI_Request req;
    MPI_Comm comm = MPI_COMM_WORLD;

    MPI_Init(NULL, NULL);
    MPI_Comm_size(comm, &N);
    MPI_Comm_rank(comm, &id);

    int range_per_node = upper / N;
    mylower = range_per_node * id;
    myupper = range_per_node * (id+1) - 1;
    if(id == N-1) {
        myupper = upper;
    }

    // Determinar la longitud del fragmento como el 60% del plaintext (al menos 5 caracteres)
    int fragmentLength = length * 0.6;
    if (fragmentLength < 5) fragmentLength = 5;

    // Establecer una posición inicial aleatoria dentro del rango válido
    srand(time(NULL));
    int startPos = rand() % (length - fragmentLength + 1);

    char search[fragmentLength + 1];
    strncpy(search, plaintext + startPos, fragmentLength);
    search[fragmentLength] = '\0';
    
    long found = 0;
    MPI_Irecv(&found, 1, MPI_LONG, MPI_ANY_SOURCE, MPI_ANY_TAG, comm, &req);

    for(int i = mylower; i < myupper && !found; ++i) {
        if(tryKey(i, ciphertext, length, search)) {
            found = i;
            for(int node = 0; node < N; node++) {
                if(node != id){
                    MPI_Send(&found, 1, MPI_LONG, node, 0, MPI_COMM_WORLD);
                }
            }
            break;
        }
    }


    if(id == 0) { // nodo maestro
        MPI_Wait(&req, &st);
        unsigned char decrypted[length+1];
        decrypt_message(found, ciphertext, decrypted, length);
        decrypted[length] = 0;
        printf("Key found: %li\nDecrypted text: %s\n", found, decrypted);
    }

    MPI_Finalize();

    return 0;
}
