// Autores
// Juan Avila 20090
// Manuel Archila 161250
// Diego Franco 20240

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <mpi.h>
#include <openssl/des.h>
#include <time.h>
#include <stdlib.h>
#include <pthread.h>

#define BLOCK_SIZE 8
#define FOUND_TAG 1

// Ajusta la paridad de la llave DES
// Recibe un puntero a la llave
// Modifica la llave en el lugar y no devuelve nada
void adjust_key_parity(uint64_t *key) {
    uint64_t adjusted_key = 0;
    for (int i = 0; i < 8; ++i) {
        *key <<= 1;
        adjusted_key += (*key & (0xFEULL << (i * 8)));
    }
    DES_set_odd_parity((DES_cblock *)&adjusted_key);
    *key = adjusted_key;
}

// Encripta un mensaje usando DES
// Recibe la llave, el texto plano, el texto cifrado y la longitud del texto
// Modifica el texto cifrado en el lugar y no devuelve nada
void encrypt_message(uint64_t key, unsigned char *plaintext, unsigned char *ciphertext, int length) {
    adjust_key_parity(&key);
    DES_key_schedule schedule;
    DES_set_key_unchecked((const_DES_cblock *)&key, &schedule);
    for (int i = 0; i < length; i += BLOCK_SIZE) {
        DES_ecb_encrypt(plaintext + i, ciphertext + i, &schedule, DES_ENCRYPT);
    }
}

// Desencripta un mensaje usando DES
// Recibe la llave, el texto cifrado, el texto plano y la longitud del texto
// Modifica el texto plano en el lugar y no devuelve nada
void decrypt_message(uint64_t key, unsigned char *ciphertext, unsigned char *decryptedtext, int length) {
    adjust_key_parity(&key);
    DES_key_schedule schedule;
    DES_set_key_unchecked((const_DES_cblock *)&key, &schedule);
    for (int i = 0; i < length; i += BLOCK_SIZE) {
        DES_ecb_encrypt(ciphertext + i, decryptedtext + i, &schedule, DES_DECRYPT);
    }
}

// Prueba una llave DES para ver si descifra el texto cifrado y contiene el texto de búsqueda
// Recibe la llave, el texto cifrado, la longitud del texto y el texto de búsqueda
// Devuelve 1 si la llave es correcta, 0 en caso contrario
int tryKey(uint64_t key, unsigned char *ciph, int len, char *search) {
    unsigned char temp[len+1];
    memcpy(temp, ciph, len);
    decrypt_message(key, temp, temp, len);
    temp[len] = 0;
    return strstr((char *)temp, search) != NULL;
}

// Estructura con la que se guardan los
// argumentos de cada hilo
typedef struct {
    long start;
    long end;
    unsigned char *ciphertext;
    int length;
    char *search;
    long *found;
    int *flag;
    MPI_Request *req;
    MPI_Status *st;
    int N;
    int id;
} ThreadArgs;

// Función que ejecuta cada hilo para probar las llaves DES
// Recibe un puntero a los argumentos del hilo
// Devuelve NULL
void *tryKeyThread(void *arguments) {
    ThreadArgs *args = (ThreadArgs *)arguments;

    for(long i = args->start; i < args->end && !(*args->flag); i += 2) {
        // Comprobar regularmente si se ha encontrado la clave en otro proceso
        int mpiFlag;
        MPI_Test(args->req, &mpiFlag, args->st);
        if (mpiFlag || *args->flag) {
            break;  // Si hemos recibido un mensaje o flag está establecido, salimos del bucle
        }
        
        if(tryKey(i, args->ciphertext, args->length, args->search)) {
            *args->found = i;
            *args->flag = 1;
            for(int node = 0; node < args->N; node++) {
                if(node != args->id){
                    MPI_Send(args->found, 1, MPI_LONG, node, FOUND_TAG, MPI_COMM_WORLD);
                }
            }
            break;
        }
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    // Leer archivo de texto 
    FILE *fp;
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    double start_time, end_time;
    fp = fopen("entrada.txt", "r");
    if (fp == NULL)
        exit(EXIT_FAILURE);

    while ((read = getline(&line, &len, fp)) != -1) {
        // Do nothing, just reading
    }

    fclose(fp);
    printf("Texto recibido: %s\n", line);

    uint64_t key = strtoull(argv[1], NULL, 10); // 10 indica base decimal
    printf("Key: %llu\n", key);

    int length = strlen(line);
    unsigned char ciphertext[length];
    encrypt_message(key, (unsigned char *)line, ciphertext, length);


    int N, id;
    long upper = (1L << 56); // límite superior para las llaves DES 2^56
    long mylower, myupper;
    MPI_Status st;
    MPI_Request req;
    MPI_Comm comm = MPI_COMM_WORLD;

    MPI_Init(NULL, NULL);
    MPI_Comm_size(comm, &N);
    MPI_Comm_rank(comm, &id);

    start_time = MPI_Wtime();
    long range_per_node = upper / N;
    mylower = range_per_node * id;
    myupper = range_per_node * (id+1) - 1;
    if(id == N-1) {
        myupper = upper;
    }


    // Determinar la longitud del fragmento como el 60% del line (al menos 5 caracteres)
    int fragmentLength = length * 0.6;
    if (fragmentLength < 5) fragmentLength = 5;

    // Establecer una posición inicial aleatoria dentro del rango válido
    srand(time(NULL));
    int startPos = rand() % (length - fragmentLength + 1);

    char search[fragmentLength + 1];
    strncpy(search, line + startPos, fragmentLength);
    search[fragmentLength] = '\0';

    long found = 0;
    int flag = 0;
    MPI_Irecv(&found, 1, MPI_LONG, MPI_ANY_SOURCE, FOUND_TAG, MPI_COMM_WORLD, &req);

    pthread_t thread1, thread2;
    ThreadArgs args1 = {
        mylower + (mylower % 2 == 0 ? 0 : 1),
        myupper,
        ciphertext,
        length,
        search,
        &found,
        &flag,
        &req,
        &st,
        N,
        id
    };
    
    ThreadArgs args2 = {
        mylower + (mylower % 2 == 0 ? 1 : 0),
        myupper,
        ciphertext,
        length,
        search,
        &found,
        &flag,
        &req,
        &st,
        N,
        id
    };

    pthread_create(&thread1, NULL, tryKeyThread, &args1);
    pthread_create(&thread2, NULL, tryKeyThread, &args2);

    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);

    if(found) {
        for(int node = 0; node < N; node++) {
            if(node != id){
                MPI_Send(&found, 1, MPI_LONG, node, FOUND_TAG, MPI_COMM_WORLD);
            }
        }
    }

    if(id == 0) {
        MPI_Wait(&req, &st);
        unsigned char decrypted[length+1];
        decrypt_message(found, ciphertext, decrypted, length);
        decrypted[length] = 0;
        printf("Key found: %li\nDecrypted text: %s\n", found, decrypted);
    }

    end_time = MPI_Wtime();

    if(id == 0) {
        printf("Duration: %f seconds\n", end_time - start_time);
    }

    MPI_Finalize();

    return 0;
}
