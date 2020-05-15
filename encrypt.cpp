#include "encrypt.h"


void HexCode(unsigned char *data, int len)
{
    int i = 0;
    for (; i < len; i++)
        printf("%02x", (unsigned int)data[i]);
    printf("\n");
}

void conv_key(char* pwd, uint8_t* key)
{
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx,pwd,strlen(pwd));
    MD5_Final(key,&ctx);
    return;
}

//pin 分配的空间必须大于 len + 16
uint32_t add_padding(uint8_t* pin, uint32_t len){
    uint8_t offset = 16 - len % 16;
    pin[len + offset - 1] = offset;
    return (len + offset);
}

uint32_t remove_padding(uint8_t* pin, uint32_t len){
    return len - pin[len - 1];
}

uint32_t encrypt(uint8_t* pin, uint8_t* pout, uint32_t len, char* pwd){
    AES_KEY akey;
    uint8_t key[16]={0};
    uint8_t vi[16]={0};

    uint32_t reallen = add_padding(pin, len);
    conv_key(pwd,key);
    AES_set_encrypt_key(key,128,&akey);
    AES_cbc_encrypt(pin,pout,reallen,&akey,vi,AES_ENCRYPT);
    return reallen;
}

uint32_t decrypt(uint8_t* pin, uint8_t* pout, uint32_t len, char* pwd){
    AES_KEY akey;
    uint8_t key[16]={0};
    uint8_t vi[16]={0};
    conv_key(pwd,key);
    AES_set_decrypt_key(key,128,&akey);
    AES_cbc_encrypt(pin,pout,len,&akey,vi,AES_DECRYPT);
    uint32_t reallen = remove_padding(pout, len);
    return reallen;
}

void fillrandom(uint8_t* pin, uint32_t inlen){
    srand(time(0));
    for (uint32_t i = 0; i < inlen; i++)
    {
       pin[i] = rand()%256;
    }
    
}

bool check(uint8_t* pin, uint8_t* pout, uint32_t len){
    for (uint32_t i = 0; i < len; i++)
    {
        if(pin[i] != pout[i])
            return false;
    }
    return true;
}
