#include <iostream>
#include <sstream>
#include <pthread.h>
#include <iomanip>
#include "socket/simplesocket.h"
#include "socket/serversocket.h"
#include "socket/transfer.hpp"
#include "crypto/rsa.hpp"
#include "crypto/aes.hpp"

PubKey recv_pub_key(simplesocket *c, void *dest)
{
  PubKey pubkey;
  uint32_t pub_n_bytes, pub_e_bytes;

  dest = recv_data<simplesocket *>(c, dest, pub_n_bytes);
  mpz_set_str(pubkey.n, (const char *)dest, 16);

  dest = recv_data<simplesocket *>(c, nullptr, pub_e_bytes);
  mpz_set_str(pubkey.e, (const char *)dest, 16);

  std::free(dest);

  return pubkey;
}

uint8_t * get_aes_key(void *dest, uint32_t key_bytes, uint32_t &key_size)
{
  std::srand((uint32_t)std::time(nullptr));

  AES aes;
  key_size = key_bytes + aes.block_size;

  if (dest) dest = std::realloc(dest, key_size);
  else dest = std::malloc(key_size);

  uint8_t *key = (uint8_t *)dest;

  for (uint32_t i = 0; i < key_size; i++)
    key[i] = std::rand() & 0xff;
  
  return key;
}

void share_aes_key(simplesocket *c, const uint8_t *aeskey, uint32_t key_size, const PubKey &pubkey)
{
  uint8_t *enc_key; uint32_t enc_key_bytes;
  enc_key = new uint8_t[key_size];
  std::memcpy(enc_key, aeskey, key_size);

  RSA rsa;
  std::tie(enc_key, enc_key_bytes) = rsa.encrypt(enc_key, enc_key, key_size, pubkey);
  send_data<simplesocket *>(c, enc_key, enc_key_bytes);

  delete[] enc_key;
}

void interactive(simplesocket *c, const uint8_t *aeskey, uint32_t key_size)
{
  std::string ct_buf;
  uint8_t *pt, *ct = nullptr;
  uint32_t ptb, ctb;

  PKCS7 pkcs7; AES aes;
  uint32_t key_bytes = key_size - aes.block_size;
  const uint8_t *aesiv = aeskey + key_bytes;

  while (true)
  {
    ct = (uint8_t *)recv_data<simplesocket *>(c, ct, ctb);

    std::tie(pt, ptb) = aes.decrypt(ct, ct, ctb, aeskey, key_bytes, aesiv);
    std::tie(pt, ptb) = pkcs7.unpad(pt, pt, ptb, aes.block_size);

    std::cout << "message: ";
    for (uint32_t i = 0; i < ptb; i++)
      std::cout << pt[i];
    std::cout << "\n\n";

    ct_buf.clear();
  }

  std::free(ct);
}

void * serve(void *cv)
{
  std::cout << "connecting to client ...\n";
  simplesocket *c = (simplesocket *)cv; 
  std::cout << "connection complete!\n\n";

  std::string buffer; uint32_t key_size;

  std::cout << "receiving public rsa key ...\n";
  PubKey pubkey = recv_pub_key(c, nullptr);
  std::cout << "received public rsa key!\n\n";

  std::cout << "generating aes key ...\n";
  uint8_t *aeskey = get_aes_key(nullptr, 32, key_size);
  std::cout << "generated aes key!\n\n";

  std::cout << "sharing aes key ...\n";
  share_aes_key(c, aeskey, key_size, pubkey);
  std::cout << "shared aes key!\n\n";

  RSA rsa; AES aes;

  interactive(c, aeskey, key_size);

  delete c;
  std::cout << "connection closed!\n\n";

  std::free(aeskey);

  return nullptr;
}
 
int main(int argc, char *argv[])
{
  if (argc < 2)
  {
    std::cerr << "Usage: " << argv[0] << " <port>" << endl;
    exit(1);
  }

  std::string hostname("0.0.0.0"); uint16_t port;
  std::stringstream (argv[1]) >> port;

  try
  {
    serversocket *s = new serversocket(port);
    std::cout << "server listening at " << hostname << ":" << port << "\n\n";

    while (true)
    {
      simplesocket *c = s->accept();
      pthread_t *th = new pthread_t;
      pthread_create(th, nullptr, serve, (void *)c);
    }

    s->close();
    delete s;
    std::cout << "server closed!\n\n";
  }
  catch (const std::exception &exc)
  {
    std::cerr << "server closed!\n\n";
    return 1;
  }

  return 0;
}
