#include <iostream>
#include "sock5.h"
#include "encrypt.h"
using namespace std;


uint32_t send_all(m_sock sock, const char *data, uint32_t len)
{
    uint32_t sentbytes = 0;
    uint32_t n;
    while (true)
    {
        n = send(sock, data + sentbytes, len - sentbytes, 0);
        if (n < 0)
            return n;
        sentbytes += n;
        if (sentbytes == len)
            return sentbytes;
    }
    return -1;
}

void handle_tcp(m_sock local, m_sock remote)
{
    fd_set rdset;
    timeval t = {0, 100000};
    int ret = 0;
    char read_buf[4097];
    uint8_t enc_buf[4097+16];
    int rdlen;
    uint32_t enclen;
    int wtlen;
    while (true)
    {
        FD_ZERO(&rdset);
        FD_SET(local, &rdset);
        FD_SET(remote, &rdset);
        ret = select(NULL, &rdset, NULL, NULL, &t);
        if (ret < 0)
        {
            cout << "select error " << ret << " " << WSAGetLastError() << endl;
            break;
        }
        if (FD_ISSET(remote, &rdset))
        {
            rdlen = recv(remote, read_buf, 4096, 0);
            enclen = decrypt((uint8_t*)read_buf,enc_buf,rdlen,"zxcasdqwe");
            if (rdlen <= 0)
                break;
            wtlen = send_all(local, (const char*)enc_buf, enclen);
            if (wtlen < enclen)
                break;
            cout << "Remote -> Local" << endl;
        }
        if (FD_ISSET(local, &rdset))
        {
            rdlen = recv(local, read_buf, 4096, 0);
            if (rdlen <= 0)
                break;
            enclen = encrypt((uint8_t*)read_buf,enc_buf,rdlen,"zxcasdqwe");
            wtlen = send_all(remote, (const char*)enc_buf, enclen);
            if (wtlen < enclen)
                break;
            cout << "Local -> Remote" << endl;
        }
    }
}

void handle_local(m_sock sockfd)
{
    char recv_buf[1024];
    char send_buf[1024];
    int len,encryptlen;
    uint8_t enc_buf[1200]={0};
    len = recv(sockfd, recv_buf, sizeof(ST_AUTH_REQ), 0);
    if (((ST_AUTH_REQ *)recv_buf)->ver != PROTOCOL_VERSION)
    {
        cerr << "unsupport version!" << endl;
        ((ST_AUTH_RPL *)recv_buf)->ver = PROTOCOL_VERSION;
        ((ST_AUTH_RPL *)recv_buf)->method = AUTH_METHOD_NO_ACCEPTABLE;
        send(sockfd, send_buf, sizeof(ST_AUTH_RPL), 0);
        return;
    }
    ((ST_AUTH_RPL *)send_buf)->ver = PROTOCOL_VERSION;
    ((ST_AUTH_RPL *)send_buf)->method = AUTH_METHOD_NONE;
    send(sockfd, send_buf, sizeof(ST_AUTH_RPL), 0);

    len = recv(sockfd, recv_buf, 1024, 0);

    SOCKET remote = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (remote == INVALID_SOCKET)
    {
        cerr << "socket failed" << endl;
        return;
    }
    const char optval = 1;
    setsockopt(remote, IPPROTO_TCP, TCP_NODELAY, &optval, 1);

    SOCKADDR_IN remote_addr;
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(9697);
    remote_addr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");

    int ret = connect(remote, (SOCKADDR *)&remote_addr, sizeof(SOCKADDR));
    if (SOCKET_ERROR == ret)
    {
        cerr << "socket connect failed\n";
        closesocket(remote);
        return;
    }
    encryptlen = encrypt((uint8_t*)recv_buf,enc_buf,len,"zxcasdqwe");
    send(remote, (const char*)enc_buf, encryptlen, 0);
    len = recv(remote, recv_buf, 1024, 0);
    encryptlen = decrypt((uint8_t*)recv_buf,enc_buf,len,"zxcasdqwe");
    len = send(sockfd, (const char*)enc_buf, encryptlen, 0);
    if (len == 10)
    {
        cout << "remote server connected." << endl;
    }
    else
    {
        closesocket(sockfd);
        closesocket(remote);
        return;
    }

    handle_tcp(sockfd, remote);
    cout << "thread " << this_thread::get_id() << " exit." << endl;
    closesocket(sockfd);
    closesocket(remote);
    return;
}

void handle_remote(m_sock sockfd)
{
    char recv_buf[1024] = {0};
    char send_buf[1024] = {0};
    uint8_t enc_buf[1200] = {0};
    uint32_t enclen = 0;
    char doman[256] = {0};
    int len = recv(sockfd, recv_buf, 1023, 0);
    enclen = decrypt((uint8_t*)recv_buf,enc_buf,len,"zxcasdqwe");
    if (((ST_CONN_REQ *)recv_buf)->cmd != CMD_CONNECT)
    {
        cerr << "unsupport CMD!" << endl;
        closesocket(sockfd);
        return;
    }

    uint8_t atyp = ((ST_CONN_REQ *)enc_buf)->atyp;

    SOCKADDR_IN remote_addr;
    remote_addr.sin_family = AF_INET;

    if (atyp == ADDR_TYPE_IP)
    {
        remote_addr.sin_addr.S_un.S_addr = ((ST_CONN_REQ *)enc_buf)->dst.ip.addr.S_un.S_addr;
        remote_addr.sin_port = ntohs(((ST_CONN_REQ *)enc_buf)->dst.ip.port);
    }
    else if (atyp == ADDR_TYPE_DOMAIN)
    {
        uint8_t strl = ((ST_CONN_REQ *)enc_buf)->dst.domain.len;
        strncpy_s(doman, (char *)&(((ST_CONN_REQ *)enc_buf)->dst.domain.pstr), strl);
        remote_addr.sin_port = *((uint16_t *)(enc_buf + 5 + strl));
        hostent *phost = gethostbyname((const char *)doman);
        memmove(&(remote_addr.sin_addr), phost->h_addr, phost->h_length);
        cout << "thread" << this_thread::get_id() << " IP addr " << inet_ntoa(remote_addr.sin_addr) << endl;
        cout << doman << ntohs(remote_addr.sin_port) << endl;
    }
    else
    {
        cerr << "unsupport addr type" << endl;
        closesocket(sockfd);
        return;
    }

    ((ST_CONN_RPL *)send_buf)->ver = PROTOCOL_VERSION;
    ((ST_CONN_RPL *)send_buf)->atyp = ADDR_TYPE_IP;
    ((ST_CONN_RPL *)send_buf)->bnd.ip.addr.S_un.S_addr = INADDR_ANY;
    ((ST_CONN_RPL *)send_buf)->bnd.ip.port = htons(9495);

    enclen = encrypt((uint8_t*)recv_buf,enc_buf,len,"zxcasdqwe");
    len = send(sockfd, (const char*)enc_buf, enclen, 0);
    if (len < enclen)
    {
        cerr << "establish connect failed\n";
        closesocket(sockfd);
        return;
    }

    SOCKET remote = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (remote == INVALID_SOCKET)
    {
        cerr << "socket failed" << endl;
        return;
    }
    const char optval = 1;
    setsockopt(remote, IPPROTO_TCP, TCP_NODELAY, &optval, 1);
    int ret = connect(remote, (SOCKADDR *)&remote_addr, sizeof(SOCKADDR));
    if (SOCKET_ERROR == ret)
    {
        cerr << "socket connect failed\n";
        closesocket(remote);
        closesocket(sockfd);
        return;
    }

    handle_tcp(sockfd, remote);
    closesocket(remote);
    closesocket(sockfd);
    return;
}