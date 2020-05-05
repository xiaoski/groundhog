#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

using namespace std;

void HexCode(unsigned char *data, int len)
{
    int i = 0;
    for (; i < len; i++)
        printf("%02x", (unsigned int)data[i]);
    printf("\n");
}

int main(int argc, char *argv[])
{
    const int len = 3;
    unsigned char userkey[AES_BLOCK_SIZE];
    unsigned char *data = (unsigned char *)malloc(AES_BLOCK_SIZE * len);
    unsigned char *cipher = (unsigned char *)malloc(AES_BLOCK_SIZE * len);
    unsigned char *plain = (unsigned char *)malloc(AES_BLOCK_SIZE * len);
    int i;
    AES_KEY key;

    memset((void *)userkey, 0, AES_BLOCK_SIZE);
    memset((void *)data, 0, AES_BLOCK_SIZE * len);
    memset((void *)cipher, 0, AES_BLOCK_SIZE * len);
    memset((void *)plain, 0, AES_BLOCK_SIZE * len);

    strcpy((char *)userkey, "userkey");
    strcpy((char *)data, "original text");
    printf("original:");
    HexCode(data, AES_BLOCK_SIZE * len);
    AES_set_encrypt_key(userkey, 128, &key);

    for (i = 0; i < len; i++)
        AES_ecb_encrypt(data + i * AES_BLOCK_SIZE, cipher + i * AES_BLOCK_SIZE, &key, AES_ENCRYPT);
    printf("  cipher:");
    HexCode(cipher, AES_BLOCK_SIZE * len);

    AES_set_decrypt_key(userkey, 128, &key);
    for (i = 0; i < len; i++)
        AES_ecb_encrypt(cipher + i * AES_BLOCK_SIZE, plain + i * AES_BLOCK_SIZE, &key, AES_DECRYPT);
    printf("   plain:");
    HexCode(plain, AES_BLOCK_SIZE * len);

    if (strcmp((const char *)data, (const char *)plain) == 0)
    {
        printf("test result: pass\n");
    }
    else
    {
        printf("test result: fail\n");
    }

    free(data);
    free(cipher);
    free(plain);
    return 0;
}