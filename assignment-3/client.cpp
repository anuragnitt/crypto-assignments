#include <iostream>
#include <sstream>
#include <pthread.h>
#include <iomanip>
#include "socket/simplesocket.h"
#include "socket/clientsocket.h"
#include "socket/transfer.hpp"
#include "crypto/rsa.hpp"
#include "crypto/aes.hpp"

void share_pub_key(clientsocket *s, const PubKey &pubkey)
{
  char *pub_n = mpz_get_str(nullptr, 16, pubkey.n);
  send_data<clientsocket *>(s, pub_n, std::strlen(pub_n));
  delete[] pub_n;

  char *pub_e = mpz_get_str(nullptr, 16, pubkey.e);
  send_data<clientsocket *>(s, pub_e, std::strlen(pub_e));
  delete[] pub_e;
}

uint8_t * recv_aes_key(clientsocket *s, const PrivKey privkey, void *dest, uint32_t &n_bytes)
{
  dest = recv_data<clientsocket *>(s, dest, n_bytes);

  uint8_t *key; RSA rsa;
  std::tie(key, n_bytes) = rsa.decrypt(dest, dest, n_bytes, privkey);

  return key;
}

void interactive(clientsocket *s, const uint8_t *aeskey, uint32_t key_size)
{
  std::string pt_buf, ct_buf;
  uint8_t *pt = nullptr, *ct;
  uint32_t ptb, ctb;

  PKCS7 pkcs7; AES aes;
  uint32_t key_bytes = key_size - aes.block_size;
  const uint8_t *aesiv = aeskey + key_bytes;

  std::cout << "(send 'exit' to close connection)\n";

  while (true)
  {
    std::cout << "\nmessage: ";
    std::getline(std::cin, pt_buf);

    if (pt_buf.compare("exit") == 0) return;

    ptb = pt_buf.length();
    pt = (uint8_t *)std::realloc(pt, ptb);
    std::memcpy(pt, pt_buf.data(), ptb);

    std::tie(pt, ptb) = pkcs7.pad(pt, pt, ptb, aes.block_size);
    std::tie(ct, ctb) = aes.encrypt(pt, pt, ptb, aeskey, key_bytes, aesiv);

    send_data<clientsocket *>(s, ct, ctb);

    pt_buf.clear();
    ct_buf.clear();
  }

  std::free(pt);
}

int main(int argc, char *argv[])
{
  if (argc < 2)
  {
    cerr << "Usage: " << argv[0] << " <port>" << endl;
    exit(1);
  }

  std::string hostname("0.0.0.0"); uint16_t port;
  std::stringstream (argv[1]) >> port;

  try
  {
    std::cout << "connecting to server at " << hostname << ":" << port << "...\n";
    clientsocket *s = new clientsocket(hostname.c_str(), port);
    s->connect();
    std::cout << "connection complete!\n\n";

    std::cout << "generating rsa key ...\n";
    PrivKey privkey;
    privkey.random(1024, 1024);
    PubKey pubkey(privkey);
    std::cout << "generated rsa key!\n\n";

    std::cout << "sharing public rsa key ...\n";
    share_pub_key(s, pubkey);
    std::cout << "shared public rsa key!\n\n";

    std::cout << "receiving aes key ...\n";
    uint8_t *aeskey; uint32_t key_size;
    aeskey = recv_aes_key(s, privkey, nullptr, key_size);
    std::cout << "received aes key!\n\n";

    interactive(s, aeskey, key_size);

    s->close();
    std::cout << "connection closed!\n\n";

    std::free(aeskey);
  }
  catch (const std::exception &exc)
  {
    std::cout << "connection closed!\n\n";
    return 1;
  }

  return 0;
}
