#include <cstdio>
#include "encrypt.h"

using namespace std;

int main(int argc, char *argv[])
{
    uint8_t origin[5000] = {0};
    uint8_t encrypted[5000] = {0};
    uint8_t decrypted[5000] = {0};
    uint32_t real = 0;

    fillrandom(origin, 100);
    HexCode(origin, 100);

    real = encrypt(origin, encrypted, 100, "hello world");
    HexCode(encrypted, real);

    real = decrypt(encrypted, decrypted, real, "hello world");
    HexCode(decrypted, real);


    printf("%s", check(origin, decrypted, 100)?"pass":"fail");

    return 0;
}