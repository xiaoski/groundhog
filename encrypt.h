#ifndef __ENCRYPT_H__
#define __ENCRYPT_H__

#include <stdint.h>
#include <cstring>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/md5.h>

void HexCode(unsigned char *data, int len);
void conv_key(char* pwd, uint8_t* key);
uint32_t add_padding(uint8_t* pin, uint32_t len);
uint32_t remove_padding(uint8_t* pin, uint32_t len);
uint32_t encrypt(uint8_t* pin, uint8_t* pout, uint32_t len, char* pwd);
uint32_t decrypt(uint8_t* pin, uint8_t* pout, uint32_t len, char* pwd);
void fillrandom(uint8_t* pin, uint32_t inlen);
bool check(uint8_t* pin, uint8_t* pout, uint32_t len);

#endif