#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/des.h>

void decrypt(long key, char *ciph, int len) {
  DES_key_schedule schedule;
  DES_set_key((const_DES_cblock *)&key, &schedule);
  DES_decrypt((const_DES_cblock *)ciph, (DES_cblock *)ciph, &schedule);
}

void encrypt(long key, char *ciph, int len) {
  DES_key_schedule schedule;
  DES_set_key((const_DES_cblock *)&key, &schedule);
  DES_encrypt((const_DES_cblock *)ciph, (DES_cblock *)ciph, &schedule);
}

char search[] = " the ";

int tryKey(long key, char *ciph, int len) {
  char temp[len + 1];
  memcpy(temp, ciph, len);
  temp[len] = 0;
  decrypt(key, temp, len);
  return strstr((char *)temp, search) != NULL;
}

unsigned char cipher[] = {
    108, 245, 65, 63, 125, 200, 150, 66, 17, 170, 207, 170,
    34, 31, 70, 215, 0};

int main() {
  long upper = (1L << 56); //upper bound DES keys 2^56
  long found = 0;
  for (long i = 0; i < upper; ++i) {
    if (tryKey(i, (char *)cipher, strlen(cipher))) {
      found = i;
      break;
    }
  }
  decrypt(found, (char *)cipher, strlen(cipher));
  printf("%li %s\n", found, cipher);
  return 0;
}
