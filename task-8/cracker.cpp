#include <sodium.h>
#include <cstring>
#include <functional>
#include <algorithm>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

void printNBytes(unsigned char *start, int nBytes);

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

typedef struct networkMessage {
    unsigned char *nonce;
    unsigned char *cipher;
} networkMessage;

typedef struct encryptedMessage {
    networkMessage *message;
    int time;
    int size;
    encryptedMessage *next;
    encryptedMessage *prev;
} encryptedMessage;

void printLengthOfLL(encryptedMessage *LL) {
    int i = 0;
    encryptedMessage *cur = LL;
    while (cur) {
        i += 1;
        cur = cur->next;
    }
    printf("%d Messages Left\n", i);
}

void parseNetworkTraffic(unsigned char *message, networkMessage *out, int size) {
    for (int i = 0; i < 24; i++) {
        memcpy(out->nonce + i, message + 4 + i, 1);
    }
    for (int i = 0; i < size; i++) {
        memcpy(out->cipher + i, message + 28 + i, 1);
    }
}

void printEncryptedBytes(unsigned char *start) {
    for (int i = 0; i < 16; i++) {
        printf("%02x ", start[i]);
    }
    printf("- ");

    for (int i = 0; i < 14; i++) {
        printf("%02x ", start[16 + i]);
    }
    printf("- ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", start[30 + i]);
    }

    printf("- ");

    for (int i = 0; i < 4; i++) {
        printf("%02x ", start[46 + i]);
    }
    printf("\n");
    printf("\t\tClutter\t\t\t\t\t\tFrontMagic\t\t\t\t\tUUID\t\t\t\tEndMagic\n");
}

void setupMessages(encryptedMessage **out, char *pcap) {
    FILE *fp = fopen(pcap, "r");
    char buf[0x3000];
    unsigned char binBuf[0x40000];
    if (fp == nullptr) {
        printf("failed to open pcap data file!\n");
        exit(1);
    }
    auto *temp = (encryptedMessage *) calloc(1, sizeof(encryptedMessage));
    int i = 0;
    while (fgets(buf, 0x3000, fp)) {
        buf[strcspn(buf, "\n")] = 0;

        auto *curMessage = (encryptedMessage *) calloc(1, sizeof(encryptedMessage));
        char *comma = strchr(buf, ',');
        *comma = '\x00';
        hex2bin((const char *)buf, binBuf);
        char *pTime = comma + 1;
        curMessage->message = (networkMessage *) calloc(1, sizeof(networkMessage));
        curMessage->message->nonce = (unsigned char *) calloc(24, sizeof(unsigned char));
        curMessage->message->cipher = (unsigned char *) calloc(strlen(buf) + 1, sizeof(unsigned char));

        curMessage->size = (strlen(buf) / 2);
        parseNetworkTraffic((unsigned char *)binBuf, curMessage->message, strlen(buf) / 2);
        char *pEnd;
        curMessage->time = strtol(pTime, &pEnd, 10);

        if (i == 0) {
            *out = temp = curMessage;
            curMessage->prev = nullptr;
        } else {
            temp->next = curMessage;
            curMessage->prev = temp;
            temp = curMessage;
        }
        i++;
    }

    temp->next = nullptr;
}

void generateData(unsigned char *username, unsigned char *time, unsigned char *version, unsigned char *out) {
    size_t ulen = strlen((const char *) username);
    memcpy(out, username, ulen);
    memcpy(out + strlen((const char *) out), version, strlen((const char *) version));
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

void generateKey(unsigned char *data, unsigned char *key) {
    int iVar2;
    uint uVar3;
    uint uVar4;
    uint a, b, c, d, e, f, g, h, i, j, n, o, p, q, r, s, t, u;
    uint t1;
    uint t2;
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
                (~e & g ^ e & f) + k[i];
        uVar3 = b ^ c;
        uVar4 = b & c;
        h = g;
        g = f;
        f = e;
        e = iVar2 + d;
        d = c;
        c = b;
        b = a;
        a = (uVar4 ^ uVar3 & a) +
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


void printNBytes(unsigned char *start, int nBytes) {
    for (int i = 0; i < nBytes; i++) {
        printf("%02x", start[i]);
    }
    printf("\n");
}

void printDecryptedBytes(unsigned char *start, int size) {
    for (int i = 0; i < 14; i++) {
        printf("%02x ", start[i]);
    }
    printf("- ");

    for (int i = 0; i < 4; i++) {
        printf("%02x", start[14 + i]);
    }
    printf("-");
    for (int i = 0; i < 2; i++) {
        printf("%02x", start[18 + i]);
    }
    printf("-");
    for (int i = 0; i < 2; i++) {
        printf("%02x", start[20 + i]);
    }
    printf("-");
    for (int i = 0; i < 2; i++) {
        printf("%02x", start[22 + i]);
    }
    printf("-");
    for (int i = 0; i < 6; i++) {
        printf("%02x", start[24 + i]);
    }
    printf(" - ");
    for (int i = 0; i < 4; i++) {
        printf("%02x ", start[30 + i]);
    }
    printf("\nOTHER - ");
    for (int i = 34; i < size; i++) {
        printf("%02x", start[i]);
    }
    printf("\n");
    printf("RAW: \n");
    for (int i = 0; i < size; i++) {
        printf("%c", start[i]);
    }
    printf("\n");
}

void generateRandomBytes(int numBytes, unsigned char *outBuf) {
    for (int i = 0; i < numBytes; i++) {

        unsigned char c = rand();
        memcpy((void *) (outBuf + i), (void *) &c, 1);
    }
}

int main(int argc, char **argv) {
    if (argc < 3) {
        printf("Usage: %s <usernames file> <versions file> <parsed pcap data file>\n", argv[0]);
        exit(-1);
    }
    if (sodium_init() < 0) {
        printf("failed to initialize libsodium\n");
    }
    srand(time(NULL));

    auto *data = (unsigned char *) calloc(64, sizeof(unsigned char));
    auto *key = (unsigned char *) calloc(32, sizeof(unsigned char));
    generateKey(data, key);


    unsigned char m[50] = {0};
    unsigned char d[0x4000] = {0};

    auto *message = (encryptedMessage *) calloc(1, sizeof(encryptedMessage));
    setupMessages(&message, argv[3]);

    unsigned long long i = 0;
    bool success = false;

    auto *username = (char *) calloc(48, sizeof(unsigned char));
    auto *version = (char *) calloc(16, sizeof(unsigned char));
    const char *userfile = argv[1];
    const char *versionsfile = argv[2];

    int v = 0;
    time_t start = time(0);
    FILE *versionFile = fopen(versionsfile, "r");
    if (versionFile == nullptr) {
        printf("failed to open versionFile file!\n");
        exit(1);
    }
    char *versions[160001];
    while (fgets(version, 15, versionFile)) {
        if (strlen(version) < 9) {
            continue;
        }
        version[strcspn(version, "\n")] = 0;
        versions[v] = (char *) calloc(15, sizeof(char));
        strcpy(versions[v], version);
        v++;
    }
    fclose(versionFile);

    FILE *users = fopen(userfile, "r");
    if (users == nullptr) {
        printf("failed to open users file!\n");
        exit(1);
    }
    while (fgets(username, 48, users)) {
        username[strcspn(username, "\n")] = 0;

        for (int ver = 0; ver < v; ver++) {
            encryptedMessage *curMessage = message;
            while (curMessage) {
                for (int t = (curMessage->time) - 5; t < (curMessage->time) + 5; t++) {
                    char time_attempt[11] = {0};

                    sprintf(time_attempt, "%d", t);
                    memset(data, 0, 64);
                    generateData((unsigned char *) username, (unsigned char *) time_attempt,
                                 (unsigned char *) versions[ver],
                                 data);
                    generateKey(data, key);
                    i++;

                    int decrypted = crypto_secretbox_open_easy(d,
                                                               curMessage->message->cipher,
                                                               curMessage->size - 28,
                                                               curMessage->message->nonce,
                                                               key);

                    if (i % 100000000 == 0) {
                        time_t now = time(0);
                        time_t diff = now - start;

                        printf("%llu %s %s %s %zd %ld\n", i, username, time_attempt, versions[ver],
                               strlen(versions[ver]), diff);
                    }

                    if (decrypted == 0) {
                        auto *outfile = (unsigned char *) calloc(100, sizeof(char));
                        struct stat st = {0};

                        if (stat("cracked", &st) == -1) {
                            mkdir("cracked", 0700);
                        }

                        sprintf((char *) outfile, "cracked/%s", username);
                        if (decrypted == 0) {
                            FILE *fp = fopen((const char *) outfile, "a");
                            fwrite(d, 32, sizeof(char), fp);
                            fclose(fp);
                        }
                        printf("Message: ");
                        printEncryptedBytes(curMessage->message->cipher);
                        printf("Username: %s\n", username);
                        printf("Time: %s\n", time_attempt);
                        printf("Version: %s\n", versions[ver]);
                        printf("Key: ");
                        printNBytes(key, 32);
                        printf("Decrypted: ");
                        printDecryptedBytes(d, curMessage->size);
                        printf("\n");
                        memset(d, '\x00', 0x4000);
                        break;
                    }
                }
                curMessage = curMessage->next;
            }
        }
        memset(username, '\x00', 48);
    }
    fclose(users);
    return 0;
}
