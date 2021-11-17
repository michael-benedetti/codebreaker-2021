#include <sodium.h>
#include <functional>
#include <algorithm>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <netdb.h>

#define PORT "6666"
uint k[] = {
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
        0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
        0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
        0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
        0xE49B69C1, 0xEFBE4786, 0xFC19DC6, 0x240CA1CC,
        0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
        0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
        0xC6E00BF3, 0xD5A79147, 0x6CA6351, 0x14292967,
        0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
        0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
        0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
        0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
        0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
        0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
        0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
        0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};

char PUBKEY[33] = "\x13\xb0\x48\x7e\x30\x98\xa0\xb0\x0a\x96\x4b\x76\xfe\x85\x7d\x4f\xe8\x48\x02\xa7\xdf\x51\xa6\x79\xaa\x6b\x60\x80\xe9\x77\x85\x14";

void printNBytes(void *start, int nBytes) {
    for (int i = 0; i < nBytes; i++) {
        printf("%02x", ((unsigned char *) start)[i]);
    }
    printf("\n");
}


int char2int(char input) {
    if (input >= '0' && input <= '9')
        return input - '0';
    if (input >= 'A' && input <= 'F')
        return input - 'A' + 10;
    if (input >= 'a' && input <= 'f')
        return input - 'a' + 10;
    throw std::invalid_argument("Invalid input string");
}

void hex2bin(const char *src, unsigned char *target) {
    unsigned char *tCursor = target;
    const char *sCursor = src;
    while (*sCursor && sCursor[1]) {
        unsigned char t = char2int(*sCursor) * 16 + char2int(sCursor[1]);
        memcpy(tCursor++, &t, 1);
        sCursor += 2;
    }
}

void generateData(unsigned char *username, unsigned char *time, unsigned char *version, unsigned char *out) {
    size_t ulen = strlen((const char *) username);
    memcpy(out, username, ulen);
    memcpy(out + strlen((const char *) out), "+", 1);
    memcpy(out + strlen((const char *) out), version, strlen((const char *) version));
    memcpy(out + strlen((const char *) out), "+", 1);
    memcpy(out + strlen((const char *) out), time, strlen((const char *) time));
    unsigned long long bitlen = strlen((const char *) out);
    memcpy(out + strlen((const char *) out), "\x80", 1);
    for (int i = strlen((const char *) out); i < 63; i++) {
        memcpy(out + i, "\x00", 1);
    }
    bitlen = bitlen << 3;
    memcpy(out + 63, &bitlen, 1);
    if (ulen + 19 > 31) {
        bitlen = bitlen & 0xff;
        memcpy(out + 63, &bitlen, 1);
        memcpy(out + 62, "\x01", 1);
    }
}

void generateKey(unsigned char *data, unsigned char *key) {
    int iVar2;
    uint uVar3;
    uint uVar4;
    uint a, b, c, d, e, f, g, h, i, j, n, o, p, q, r, s, t, u;
    uint m[64];

    j = 0;
    for (i = 0; i < 0x10; i = i + 1) {
        m[i] = (uint) data[j + 3] |
               (uint) data[j] << 0x18 | (uint) data[j + 1] << 0x10 | (uint) data[j + 2] << 8;
        j = j + 4;
    }
    for (; i < 0x40; i = i + 1) {
        m[i] = ((m[i - 2] << 0xf | m[i - 2] >> 0x11) ^ (m[i - 2] << 0xd | m[i - 2] >> 0x13) ^
                m[i - 2] >> 10) + m[i - 7] +
               (m[i - 0xf] >> 3 ^
                (m[i - 0xf] >> 7 | m[i - 0xf] << 0x19) ^ (m[i - 0xf] << 0xe | m[i - 0xf] >> 0x12)) +
               m[i - 0x10];
    }
    a = 0x6a09e667;
    b = 0xbb67ae85;
    c = 0x3c6ef372;
    d = 0xa54ff53a;
    e = 0x510e527f;
    f = 0x9b05688c;
    g = 0x1f83d9ab;
    h = 0x5be0cd19;

    n = 0x6a09e667;
    o = 0xbb67ae85;
    p = 0x3c6ef372;
    q = 0xa54ff53a;
    r = 0x510e527f;
    s = 0x9b05688c;
    t = 0x1f83d9ab;
    u = 0x5be0cd19;

    for (i = 0; i < 0x40; i = i + 1) {
        iVar2 = m[i] + ((e >> 6 | e << 0x1a) ^ (e >> 0xb | e << 0x15) ^ (e << 7 | e >> 0x19)) + h +
                ((~e & g) ^ (e & f)) + k[i];
        uVar3 = b ^ c;
        uVar4 = b & c;
        h = g;
        g = f;
        f = e;
        e = iVar2 + d;
        d = c;
        c = b;
        b = a;
        a = (uVar4 ^ (uVar3 & a)) +
            ((a >> 2 | a << 0x1e) ^ (a >> 0xd | a << 0x13) ^ (a << 10 | a >> 0x16)) + iVar2;
    }
    n += a;
    o += b;
    p += c;
    q += d;
    r += e;
    s += f;
    t += g;
    u += h;

    for (int i = 0; i < 4; i++) {
        key[i] = (n >> (('\x03' - i) * '\b' & 0x1fU));
        key[i + 4] = (o >> (('\x03' - i) * '\b' & 0x1fU));
        key[i + 8] = (p >> (('\x03' - i) * '\b' & 0x1fU));
        key[i + 0xc] = (q >> (('\x03' - i) * '\b' & 0x1fU));
        key[i + 0x10] = (r >> (('\x03' - i) * '\b' & 0x1fU));
        key[i + 0x14] = (s >> (('\x03' - i) * '\b' & 0x1fU));
        key[i + 0x18] = (t >> (('\x03' - i) * '\b' & 0x1fU));
        key[i + 0x1c] = (u >> (('\x03' - i) * '\b' & 0x1fU));
    }
}

typedef struct message {
    unsigned char *plaintext;
    unsigned char *encrypted;
    int length;
    int encryptedLength;
    message *next;
} message;

void generateRandomBytes(int numBytes, void *outBuf) {
    for (int i = 0; i < numBytes; i++) {

        unsigned char c = rand();
        memcpy((void *) ((unsigned char *) outBuf + i), (void *) &c, 1);
    }
}

void getMessages(message **msg, char *messageFile) {
    FILE *file = fopen(messageFile, "r");
    char buf[0x1000];

    message *tmp, *cur;
    int i = 0;
    auto *uuid = (unsigned char *) calloc(0x10, sizeof(unsigned char));
    generateRandomBytes(0x10, uuid);
    while (fgets(buf, 0x1000, file)) {
        cur = (message *) calloc(1, sizeof(message));
        cur->length = strlen(buf) / 2;
        cur->plaintext = (unsigned char *) calloc(cur->length, sizeof(unsigned char));
        hex2bin((const char *) buf, cur->plaintext);
        memcpy(cur->plaintext+14, uuid, 0x10);
        if (i == 0) {
            *msg = tmp = cur;
        } else {
            tmp->next = cur;
            tmp = cur;
        }
        i++;
    }
    fclose(file);
}


static const unsigned char base64_table[65] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64_encode(const unsigned char *src, size_t len) {
    unsigned char *out, *pos;
    const unsigned char *end, *in;

    size_t olen;

    olen = 4 * ((len + 2) / 3); /* 3-byte blocks to 4-byte */

    if (olen < len)
        return std::string(); /* integer overflow */

    std::string outStr;
    outStr.resize(olen);
    out = (unsigned char *) &outStr[0];

    end = src + len;
    in = src;
    pos = out;
    while (end - in >= 3) {
        *pos++ = base64_table[in[0] >> 2];
        *pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
        *pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
        *pos++ = base64_table[in[2] & 0x3f];
        in += 3;
    }

    if (end - in) {
        *pos++ = base64_table[in[0] >> 2];
        if (end - in == 1) {
            *pos++ = base64_table[(in[0] & 0x03) << 4];
            *pos++ = '=';
        } else {
            *pos++ = base64_table[((in[0] & 0x03) << 4) |
                                  (in[1] >> 4)];
            *pos++ = base64_table[(in[1] & 0x0f) << 2];
        }
        *pos++ = '=';
    }

    return outStr;
}

char *fingerprint(char *username, char *version, char *t, char *os) {
    auto *pUsername = (char *) calloc(strlen(username) + 1 + 9, sizeof(char));
    if (pUsername == nullptr) {
        perror("malloc: pUsername");
        exit(-1);
    }
    sprintf(pUsername, "username=%s", username);
    std::string b64_username = base64_encode((const unsigned char *) pUsername, strlen(pUsername));

    auto *pVersion = (char *) calloc(strlen(version) + 1 + 12, sizeof(char));
    if (pVersion == nullptr) {
        perror("malloc: pVersion");
        exit(-1);
    }
    sprintf(pVersion, "version=%s-IQN", version);
    std::string b64_version = base64_encode((const unsigned char *) pVersion, strlen(pVersion));

    auto *pOs = (char *) calloc(strlen(os) + 1 + 10, sizeof(char));
    if (pOs == nullptr) {
        perror("malloc: pOs");
        exit(-1);
    }
    sprintf(pOs, "os=%s", os);
    std::string b64_os = base64_encode((const unsigned char *) pOs, strlen(pOs));

    auto *pTimestamp = (char *) calloc(strlen(t) + 1 + 10, sizeof(char));
    if (pTimestamp == nullptr) {
        perror("malloc: pTimestamp");
        exit(-1);
    }
    sprintf(pTimestamp, "timestamp=%s", t);
    std::string b64_time = base64_encode((const unsigned char *) pTimestamp, strlen(pTimestamp));

    int total_size = strlen(b64_username.c_str()) + strlen(b64_version.c_str()) + strlen(b64_os.c_str()) +
                     strlen(b64_time.c_str()) + 4;

    auto *base64_data = (char *) calloc(total_size, sizeof(char));
    if (base64_data == nullptr) {
        perror("malloc: base64_data");
        exit(-1);
    }
    sprintf(base64_data, "%s,%s,%s,%s", b64_username.c_str(), b64_version.c_str(), b64_os.c_str(), b64_time.c_str());

    free(pUsername);
    free(pVersion);
    free(pOs);
    free(pTimestamp);

    return base64_data;
}

int lengthHeader(int length) {
    int front;
    generateRandomBytes(2, &front);
    front = ntohs(front);

    int back = (length - front) + 0x10000;
    front = ntohs(front);
    back = htons(back);
    front = (front & 0xffff) | (back << 0x10);

    return front;
}

unsigned char *buildInitialCrypt(char *username, char *version, char *t, char *os, int *size) {
    char *fp = fingerprint(username, version, t, os);

    auto encrypted = (unsigned char *) calloc(strlen(fp) + 40, sizeof(char));
    auto *nonce = (unsigned char *) calloc(24, sizeof(unsigned char));

    generateRandomBytes(24, nonce);
    memcpy(encrypted, nonce, 24);

    auto *pk = (unsigned char *) calloc(32, sizeof(unsigned char));
    auto *sk = (unsigned char *) calloc(32, sizeof(unsigned char));

    crypto_box_curve25519xchacha20poly1305_keypair(pk, sk);
    int crypt_status = crypto_box_easy(encrypted+24, (const unsigned char *) fp, strlen(fp), nonce,
                    (const unsigned char *) PUBKEY, sk);
    printNBytes(encrypted, 111);
    if (crypt_status == -1) {
        perror("init crypt");
        exit(-1);
    }

    unsigned int lenHeader = lengthHeader(strlen(fp) + 40);
    *size = strlen(fp) + 40 + 32 + 4;

    auto final_message = (unsigned char *) calloc(*size, sizeof(unsigned char));
    memcpy(final_message, pk, 32);
    memcpy(final_message + 32, &lenHeader, 4);
    memcpy(final_message + 36, encrypted, strlen(fp) + 40);

    free(fp);
    free(nonce);
    free(pk);
    free(sk);

    return final_message;
}

void encryptMessages(message **msg, unsigned char *username, unsigned char *version, char *t) {


    auto *nonce = (unsigned char *) calloc(24, sizeof(unsigned char));
    auto *key = (unsigned char *) calloc(24, sizeof(unsigned char));
    auto *keyData = (unsigned char *) calloc(64, sizeof(unsigned char));

    generateData(username, (unsigned char *) t, version, keyData);
    generateKey(keyData, key);

    for (message *cur = *msg; cur != nullptr; cur = cur->next) {
        generateRandomBytes(24, nonce);
        cur->encryptedLength = cur->length + 44;
        cur->encrypted = (unsigned char *) calloc(cur->encryptedLength, sizeof(char));
        int encryptedLength = lengthHeader(cur->length + 40);
        memcpy(cur->encrypted, &encryptedLength, 4);
        memcpy(cur->encrypted + 4, nonce, 24);
        int crypt_status = crypto_secretbox_easy((unsigned char *) cur->encrypted + 28,
                                                 (const unsigned char *) cur->plaintext, cur->length, nonce,
                                                 (const unsigned char *) key);
        if (crypt_status != 0) {
            perror("encrypt");
            exit(-1);
        }
    }
}

int connectToLp(char *ip) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    int status = getaddrinfo(ip, PORT, &hints, &res);
    if (status == -1) {
        perror("getaddrinfo");
        exit(-1);
    }
    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock == -1) {
        perror("sock");
        exit(-1);
    }

    int conn = connect(sock, res->ai_addr, res->ai_addrlen);
    if (conn == -1) {
        perror("connect");
        exit(-1);
    }

    return sock;
}

int main(int argc, char **argv) {
    if (argc < 6) {
        printf("Usage: %s <ip> <message file> <username> <version> <os>\n", argv[0]);
        exit(-1);
    }

    char *ip = argv[1];
    char *messageFile = argv[2];
    char *username = argv[3];
    char *version = argv[4];
    char *os = argv[5];

    if (sodium_init() < 0) {
        perror("sodium");
        exit(-1);
    }
    srand(time(nullptr));

    auto *msg = (message *) calloc(1, sizeof(message));
    getMessages(&msg, messageFile);

    char t[11];
    sprintf(t, "%ld", time(nullptr));

    encryptMessages(&msg, (unsigned char *) username, (unsigned char *) version, t);

    int initialCryptSize;
    unsigned char *initialCrypt = buildInitialCrypt(username, version, t, os, &initialCryptSize);

    int sock = connectToLp(ip);

    send(sock, initialCrypt, initialCryptSize, 0);
    sleep(1);
    printNBytes(initialCrypt, initialCryptSize);

    for (message *cur = msg; cur != nullptr; cur = cur->next) {
        char buf[0x1000] = {0};
        char len[4];
        send(sock, cur->encrypted, cur->encryptedLength, 0);
        sleep(1);
        recv(sock, len, 4, 0);

        uint16_t size1;
        uint16_t size2;
        memcpy(&size1, len, 2);
        memcpy(&size2, len+2, 2);
        size1 = ntohs(size1);
        size2 = ntohs(size2);
        uint16_t msgsize = size1 + size2;
        printf("%hu\n", msgsize);
        printNBytes(len, 4);
        recv(sock, buf, msgsize, 0);
        printNBytes(buf, msgsize);
    }

    close(sock);
}