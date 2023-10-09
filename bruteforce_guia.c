// bruteforce_openssl.c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <mpi.h>
#include <openssl/des.h>

void decrypt(DES_cblock *key, unsigned char *ciphertext, int len, unsigned char *plaintext) {
    DES_key_schedule schedule;
    DES_set_key_checked(key, &schedule);
    DES_ecb_encrypt((const_DES_cblock *)ciphertext, (DES_cblock *)plaintext, &schedule, DES_DECRYPT);
}

void encrypt(DES_cblock *key, unsigned char *plaintext, int len, unsigned char *ciphertext) {
    DES_key_schedule schedule;
    DES_set_key_checked(key, &schedule);
    DES_ecb_encrypt((const_DES_cblock *)plaintext, (DES_cblock *)ciphertext, &schedule, DES_ENCRYPT);
}

char search[] = " the ";
int tryKey(DES_cblock *key, unsigned char *ciphertext, int len) {
    unsigned char temp[len];
    decrypt(key, ciphertext, len, temp);
    temp[len] = 0;  // Null-terminate the decrypted text
    return strstr((char *)temp, search) != NULL;
}

unsigned char plaintext[] = "Hello, World! the ";
unsigned char ciphertext[16];
int main(int argc, char *argv[]) {
    int N, id;
    DES_cblock key;
    MPI_Status st;
    MPI_Request req;
    int flag;
    MPI_Comm comm = MPI_COMM_WORLD;

    // Initialize MPI
    MPI_Init(NULL, NULL);
    MPI_Comm_size(comm, &N);
    MPI_Comm_rank(comm, &id);

    // Encrypt the plaintext using a predefined key
    memset(&key, 0, sizeof(DES_cblock));  // Zero out the key
    encrypt(&key, plaintext, sizeof(plaintext) - 1, ciphertext);

    long upper = (1L << 56);  // Upper bound for brute force search (keeping the original range)
    long mylower, myupper;
    long found = 0;

    int range_per_node = upper / N;
    mylower = range_per_node * id;
    myupper = range_per_node * (id + 1) - 1;
    if (id == N - 1) {
        myupper = upper;  // Compensate for any remainder in the last node
    }

    MPI_Irecv(&found, 1, MPI_LONG, MPI_ANY_SOURCE, MPI_ANY_TAG, comm, &req);

    for (long i = mylower; i < myupper && (found == 0); ++i) {
        memcpy(&key, &i, sizeof(long));  // Copy the current key value into the key array
        DES_set_odd_parity(&key);
        if (tryKey(&key, ciphertext, sizeof(ciphertext))) {
            found = i;
            for (int node = 0; node < N; node++) {
                MPI_Send(&found, 1, MPI_LONG, node, 0, MPI_COMM_WORLD);
            }
            break;
        }
    }

    if (id == 0) {
        MPI_Wait(&req, &st);
        memcpy(&key, &found, sizeof(long));  // Copy the found key value into the key array
        DES_set_odd_parity(&key);
        decrypt(&key, ciphertext, sizeof(ciphertext), plaintext);
        printf("%li %s\n", found, plaintext);
    }

    MPI_Finalize();
    return 0;
}
