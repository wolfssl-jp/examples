/* sample_client.c
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */
#include <stdio.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/openssl/ssl.h>

#include "sample_client.h"

#define INLINE
#define WOLFSSL_SUCCESS 1
#define SOCKET_T int
#define WOLFSSL_MAX_ERROR_SZ 80
#define SSL_SOCKET_INVALID  (SOCKET_T)(0)
#define SSL_SOCKET_IS_INVALID(s)  ((SOCKET_T)(s) < SSL_SOCKET_INVALID)
#define _WANT_WRITE WC_PENDING_E

typedef unsigned short word16;
typedef struct sockaddr_in  SOCKADDR_IN_T;

static const char *TARGETSERVER[3] =
{
    "azure.microsoft.com",
    "aws.amazon.com",
    "127.0.0.1",
};
static const word16 TARGETSERVER_PORT[3] =
{
    443, 443, 11111
};

static int err_sys(const char* msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

static WC_INLINE void build_addr(SOCKADDR_IN_T* addr, const char* peer,
                              word16 port)
{
    int useLookup = 0;
    (void)useLookup;

    if (addr == NULL)
        err_sys("invalid argument to build_addr, addr is NULL");

    memset(addr, 0, sizeof(SOCKADDR_IN_T));

    /* peer could be in human readable form */
    if ( ((size_t)peer != INADDR_ANY) && isalpha((int)peer[0])) {
        struct hostent* entry = gethostbyname(peer);

        if (entry) {
            memcpy(&addr->sin_addr.s_addr, entry->h_addr_list[0],
                   entry->h_length);
            useLookup = 1;
        }
        else
            err_sys("no entry for host");
    }

    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);

    if ((size_t)peer == INADDR_ANY)
        addr->sin_addr.s_addr = INADDR_ANY;
    else {
        if (!useLookup)
            addr->sin_addr.s_addr = inet_addr(peer);
    }

}

static WC_INLINE void tcp_socket(SOCKET_T* sockfd)
{
    int       on = 1;
    socklen_t len = sizeof(on);
    int       res;

    *sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if(SSL_SOCKET_IS_INVALID(*sockfd)) {
        err_sys("socket failed\n");
    }

    res = setsockopt(*sockfd, IPPROTO_TCP, TCP_NODELAY, &on, len);
    if (res < 0)
        err_sys("setsockopt TCP_NODELAY failed\n");
}

static WC_INLINE void tcp_connect(SOCKET_T* sockfd, const char* ip, word16 port, SSL* ssl)
{
    SOCKADDR_IN_T addr;
    build_addr(&addr, ip, port);

    tcp_socket(sockfd);

    if (connect(*sockfd, (const struct sockaddr*)&addr, sizeof(addr)) != 0)
        err_sys("tcp connect failed");
}
/* This function is to load cert file from ./certs/ folder */
/* And then try to connect azure.micosoft.com,             */
/* aws.amazon.com and local servers                        */
void client_certfolder_test()
{
    SSL_CTX*    ctx    = 0;
    SSL*        ssl    = 0;
    SOCKET_T sockfd = 0;
    char reply[1024+1];
    char buffer[WOLFSSL_MAX_ERROR_SZ];
    int ret = 0, err = 0;
    int sendSz;
    int i;

    /*1. create wolfSSL context */
    ctx    = SSL_CTX_new(SSLv23_client_method());
    /*2. load root ca files in cert/ folder */
    if (wolfSSL_CTX_load_verify_locations_ex(ctx, NULL, "./certs/",
                 WOLFSSL_LOAD_FLAG_IGNORE_ERR) != WOLFSSL_SUCCESS) {
        err_sys("can't load ca file in folder");
        wolfSSL_CTX_free(ctx);
        exit(-1);
    } else {
        printf("Loaded certs files...OK!\n");
    }
    
    /*  connect each target */
    i = 0;
    while(i < 3)
    {
        printf("please hit any key to connect %s\n", TARGETSERVER[i]);
        printf(">");
        getchar();

        /*3. create new wolfSSL object */
        ssl = SSL_new(ctx);

        /*4. connect to peer */
        tcp_connect(&sockfd, TARGETSERVER[i], TARGETSERVER_PORT[i], ssl);
        /* This function assigns a file descriptor (fd) as 
        the input/output facility for the SSL connection. */
        wolfSSL_set_fd(ssl, sockfd);

        do {
            err = 0; /* Reset error */
            /*5. call wolfSSL_connect() to start TLS handshake */
            ret = wolfSSL_connect(ssl);
            if (ret != WOLFSSL_SUCCESS) {
                err = wolfSSL_get_error(ssl, 0);
            }
        } while (err == _WANT_WRITE);

        if (ret != WOLFSSL_SUCCESS) {
            printf("SSL_connect error %d, %s\n", err,
                ERR_error_string(err, buffer));
            err_sys("SSL_connect failed");
        }
        /*6. send message to server and print reply from server */
        do {
            err = 0; /* reset error */
            ret = wolfSSL_write(ssl, "hello\n", 6);
            if (ret <= 0) {
                err = wolfSSL_get_error(ssl, 0);
            }
        } while (err == _WANT_WRITE);
        
        if (ret != 6) {
            printf("SSL_write msg error %d, %s\n", err,
                 ERR_error_string(err, buffer));
            err_sys("SSL_write failed");
        }
        
        {
            do {
                err = 0; /* reset error */
                ret = wolfSSL_read(ssl, reply, sizeof(reply)-1);
                if (ret <= 0) {
                    err = wolfSSL_get_error(ssl, 0);
                }
            } while (err == _WANT_WRITE);
        
            if (ret > 0) {
                reply[ret] = 0;
                printf("%s", reply);
                sendSz -= ret;
            }
            else {
                 printf("SSL_read msg error %d, %s\n", err,
                     ERR_error_string(err, buffer));
                 err_sys("SSL_read failed");
            }
        }
        /* disconnect from peer */
        wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
        close(sockfd);
        ssl = NULL;
        i++;
        printf("\n");
    }
    /* clean up SSL context object */
    wolfSSL_CTX_free(ctx);
}

/* entry */
int main(int argc, char** argv)
{
#if defined(DEBUG_WOLFSSL)
    wolfSSL_Debugging_ON();
#endif

    client_certfolder_test();

    return 1;
}
