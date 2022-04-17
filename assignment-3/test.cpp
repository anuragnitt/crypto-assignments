#include <iostream>
#include <ctime>
#include "aes.h"
#include "rsa.h"
using namespace std;

void print(const void *buf, uint32_t nb)
{
    std::string str;
    str.assign((char *)buf, nb);
    std::cout << str << "\n";
}

void aes_test(void)
{
    std::srand((uint32_t)std::time(nullptr));
    AES aes; PKCS7 pkcs7;

    uint8_t key[16], iv[16];
    for (int i = 0; i < 16; i++)
        key[i] = std::rand() & 0xff;
    for (int i = 0; i < 16; i++)
        iv[i] = std::rand() & 0xff;

    std::string msg("1anscind(9jklakl]4531");

    uint8_t *pt = new uint8_t[msg.length()], *ct;
    std::memcpy(pt, msg.data(), msg.length());
    uint32_t ptb, ctb;

    std::tie(pt, ptb) = pkcs7.pad(pt, pt, msg.length(), aes.block_size);
    std::tie(ct, ctb) = aes.encrypt(pt, pt, ptb, key, 16, iv);
    std::tie(pt, ptb) = aes.decrypt(pt, ct, ctb, key, 16, iv);
    std::tie(pt, ptb) = pkcs7.unpad(pt, pt, ptb, aes.block_size);

    print(pt, ptb);
    delete[] pt;
}

void rsa_test(void)
{
    PrivKey privkey;
    privkey.random(512, 512);

    PubKey pubkey(privkey);

    RSA rsa;

    uint8_t *m = new uint8_t[6];
    m[0] = 65; m[1] = 110; m[2] = 117; m[3] = 114; m[4] = 97; m[5] = 103;

    uint32_t n = 6;

    std::tie(m, n) = rsa.encrypt(m, m, n, pubkey);
    std::tie(m, n) = rsa.decrypt(m, m, n, privkey);

    for (uint32_t i = 0; i < n; i++)
        std::cout << (int)m[i] << " ";
    std::cout << "\n";

    delete[] m;
}

int main(void)
{
    aes_test();
    rsa_test();

    return 0;
}

