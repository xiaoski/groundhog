#include <iostream>
#include <vector>
#include "sock5.h"
#ifdef _WIN32
#include <winsock2.h>
#endif
using namespace std;

int main(int argc, char *argv[])
{
    WSADATA wsaData;
    WORD sockVersion = MAKEWORD(2, 2);
    if (WSAStartup(sockVersion, &wsaData) != 0)
    {
        return 0;
    }
    SOCKET sListen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sListen == INVALID_SOCKET)
    {
        printf("socket error\n");
        return 0;
    }
    const char optval = 1;
    setsockopt(sListen, SOL_SOCKET, SO_REUSEADDR, &optval, 1);
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(9495);
    sin.sin_addr.S_un.S_addr = INADDR_ANY;
    if (bind(sListen, (LPSOCKADDR)&sin, sizeof(sin)) == SOCKET_ERROR)
    {
        printf("socket error\n");
        closesocket(sListen);
        return 0;
    }
    if (listen(sListen, 5) == SOCKET_ERROR)
    {
        printf("socket error\n");
        closesocket(sListen);
        return 0;
    }
    struct sockaddr_in remoteAddr;
    SOCKET sClient;
    int nAddrLen = sizeof(remoteAddr);
    thread  *pth = nullptr;
    while (TRUE)
    {
        sClient = accept(sListen, (SOCKADDR *)&remoteAddr, &nAddrLen);
        if (sClient == SOCKET_ERROR)
        {
            printf("accept() error\n");
            break;
        }

        printf("accept a connection %lld %s:%d \r\n", sClient, inet_ntoa(remoteAddr.sin_addr), ntohs(remoteAddr.sin_port));
        pth = new thread(handle_local,sClient);
        pth->detach();
        delete pth;
        pth = nullptr;
    
    }
    closesocket(sListen);
    WSACleanup();
    return 0;
}
