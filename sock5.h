#include <stdint.h>
#include <thread>
#ifdef _WIN32
#include <winsock2.h>
typedef in_addr in_addr_t;
typedef uint16_t in_port_t;
typedef SOCKET m_sock;
#elif defined(__linux__)
typedef int m_sock;
#else
#error OS unsupport
#endif
#ifndef BYTE
typedef unsigned char BYTE;
#endif

using namespace std;

const uint8_t PROTOCOL_VERSION = 0x05;

const uint8_t AUTH_METHOD_NONE = 0x00;
const uint8_t AUTH_METHOD_GSSAPI = 0x01;
const uint8_t AUTH_METHOD_USERPSWD = 0x02;
const uint8_t AUTH_METHOD_IANA_BGN = 0x03;
const uint8_t AUTH_METHOD_IANA_END = 0x7f;
const uint8_t AUTH_METHOD_PRIVATE_BGN = 0x80;
const uint8_t AUTH_METHOD_PRIVATE_END = 0xfe;
const uint8_t AUTH_METHOD_NO_ACCEPTABLE = 0xff;

typedef struct
{
    uint8_t ver;
    uint8_t nmethods;
    uint8_t methods[255];
} ST_AUTH_REQ;

typedef struct
{
    uint8_t ver;
    uint8_t method;
} ST_AUTH_RPL;

const uint8_t CMD_CONNECT = 0x01;
const uint8_t CMD_BIND = 0x02;
const uint8_t CMD_UDP_ASSOCIATE = 0x03;

const uint8_t ADDR_TYPE_IP = 0x01;
const uint8_t ADDR_TYPE_DOMAIN = 0x03;
const uint8_t ADDR_TYPE_IPV6 = 0x04;

typedef struct
{
    uint8_t ver;
    uint8_t cmd;
    uint8_t rsv;
    uint8_t atyp;
    union {
        struct
        {
            in_addr_t addr;
            in_port_t port;
        } ip;
        struct
        {
            uint8_t len;
            uint8_t pstr;
        } domain;
        struct
        {
            uint8_t addr[16];
            in_port_t port;
        } ipv6;
    } dst;
} ST_CONN_REQ;

typedef struct reply
{
    uint8_t ver;
    uint8_t rep;
    uint8_t rsv;
    uint8_t atyp;
    union {
        struct
        {
            in_addr_t addr;
            in_port_t port;
        } ip;
        struct
        {
            uint8_t len;
            uint8_t pstr;
        } domain;
        struct
        {
            uint8_t addr[16];
            in_port_t port;
        } ipv6;
    } bnd;
} ST_CONN_RPL;

void HexCode(unsigned char *data, int len);
void handle_local(m_sock sockfd);
void handle_remote(m_sock sockfd);