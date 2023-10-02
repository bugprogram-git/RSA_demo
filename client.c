//
// Created by 404NotFound on 2023/9/26.
//
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/aes.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define SERVER_ADDR "127.0.0.1"
#define SERVER_PORT "12000"
#define SOCKLEN (sizeof(struct sockaddr))
int padding = RSA_PKCS1_PADDING;
AES_KEY *expanded;
//AES key
unsigned char key[16] = {
        0xb3, 0x01, 0x12, 0x93,
        0xe9, 0x55, 0x24, 0xa7,
        0xea, 0x66, 0x3a, 0xcb,
        0xfc, 0x7e, 0x0e, 0x1f};

RSA *createRSA(unsigned char *key, int public) {
    RSA *rsa = NULL;
    BIO *keybio;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio == NULL) {
        printf("Failed to create key BIO");
        return 0;
    }
    if (public) {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    } else {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    }
    if (rsa == NULL) {
        printf("Failed to create RSA");
    }

    return rsa;
}


int public_encrypt(unsigned char *data, int data_len, unsigned char *key,
                   unsigned char *encrypted) {
    RSA *rsa = createRSA(key, 1);
    int result = RSA_public_encrypt(data_len, data, encrypted, rsa, padding);
    return result;
}

int connect_server(char *addr, char *port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in ADDR;
    ADDR.sin_family = AF_INET;
    ADDR.sin_port = htons(atoi(port));
    //转化ip地址类型
    if (inet_pton(AF_INET, addr, &ADDR.sin_addr) != 1) {
        perror("inet_pton");
        return -1;
    }
    //连接服务器
    if (connect(fd, (struct sockaddr *) &ADDR, SOCKLEN) != 0) {
        perror("connect");
        return -1;
    }
    //返回socket
    return fd;
}

int help() {
    //帮助信息
    return 0;
}

char *recvpublickey(int fd, int keylen_len) {
    int ret = 0;
    int publickeylen = 0;
    //recv public key len from server
    ret = recv(fd, &publickeylen, keylen_len, 0);
    if (ret != keylen_len) {
        printf("print recv public len error!|n");
    }
    //malloc memory for public key
    char *publickey = (char *) malloc(publickeylen);
    //recv public key from server
    printf("recv public key from server\n");
    ret = recv(fd, publickey, publickeylen, 0);
    if (ret != publickeylen) {
        printf("recv rsa public key error!\n");
        return 0;
    }
    return publickey;
}

static bool WriteBytes(const int sk, const char *buf, const size_t n) {
    char *ptr = buf;
    while (ptr < buf + n) {
        int ret = send(sk, ptr, n - (ptr - buf), 0);
        if (ret <= 0) {
            printf("unable to send on socket\n");
            return false;
        }

        ptr += ret;
    }
    return true;
}
static int send_aes_key(int fd, unsigned char *publickey) {
    char buf[1024] = {0};
    int ret = 0;
    printf("publickey:\n");
    printf("%s\n", publickey);
    int i = public_encrypt(key, 16, publickey, buf);
    printf("encrypto message len:%d\n", i);
    ret = send(fd, &i, 4, 0);
    if (ret != 4) {
        printf("send key len error!\n");
        return 1;
    }
    ret = send(fd, buf, i, 0);
    if (ret != i) {
        printf("send secret error!\n");
        return 1;
    }
    return 0;
}



int get_secret(int fd) {
    char cryptomsg[16];
    uint8_t secret[16];
    int ret = 0;
    memset(cryptomsg,0,16);
    memset(secret,0,16);
    //receive crypt message from server
    ret = recv(fd, cryptomsg, 16, 0);
    if (ret != 16) {
        printf("error recv secret crypto message \n");
    }
    //decrypt message
    AES_KEY *expanded = (AES_KEY *) malloc(sizeof(AES_KEY));
    //get AES key
    AES_set_decrypt_key(key, 128, expanded);
    //decrypt secret
    AES_decrypt(cryptomsg, secret,expanded);
    //print secret
    printf("get secret:\n");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", secret[i]);
    }
}

int main(int argc, char **argv) {
    int ret;
    int fd = connect_server(SERVER_ADDR, SERVER_PORT);
    if (fd == -1) {
        printf("connect server failed!\n");
    }
    printf("AES key:\n");
    for (int i = 0; i<16; i++){
        printf("%02x ",key[i]);
    }
    printf("\n");
    //recv public key from server
    char *publickey = recvpublickey(fd, 4);
    send_aes_key(fd, publickey);
    get_secret(fd);
    free(publickey);



}
