#include <cstdlib>
#include <ctime>
#include <tuple>
#include <gmp.h>

static void invalid_pt_exc(void)
{
    throw std::runtime_error("invalid plaintext (pt >= n)");
}

static void invalid_ct_exc(void)
{
    throw std::runtime_error("invalid ciphertext (ct >= n)");
}

static void incompatible_keys_exc(void)
{
    throw std::runtime_error("incompatible private key and public key");
}

class PrivKey;
class PubKey;

class RSA
{
    public:

        void encrypt(mpz_t &, const mpz_t &, const PrivKey &) const;
        void encrypt(mpz_t &, const mpz_t &, const PubKey &) const;

        void decrypt(mpz_t &, const mpz_t &, const PrivKey &) const;
        void decrypt(mpz_t &, const mpz_t &, const PubKey &) const;

        std::tuple<uint8_t *, uint32_t> encrypt(void *, const void *, uint32_t, const PrivKey &) const;
        std::tuple<uint8_t *, uint32_t> encrypt(void *, const void *, uint32_t, const PubKey &) const;

        std::tuple<uint8_t *, uint32_t> decrypt(void *, const void *, uint32_t, const PrivKey &) const;
        std::tuple<uint8_t *, uint32_t> decrypt(void *, const void *, uint32_t, const PubKey &) const;
};

class PrivKey
{
    private:

        void get_rand_prime(mpz_t &, const uint32_t);

    public:

        mpz_t p;
        mpz_t q;
        mpz_t d;
        mpz_t n;
        mpz_t e;

        PrivKey(void);
        ~PrivKey();

        void random(const uint32_t, const uint32_t);
};

class PubKey
{
    public:

        mpz_t n;
        mpz_t e;

        PubKey(void);
        PubKey(const PrivKey &);
        ~PubKey();

        void construct(const PrivKey &);
};

PrivKey::PrivKey(void)
{
    std::srand((uint32_t)std::time(nullptr));

    mpz_init(this->p);
    mpz_set_str(this->p, "0", 10);

    mpz_init(this->q);
    mpz_set_str(this->q, "0", 10);

    mpz_init(this->d);
    mpz_set_str(this->d, "0", 10);

    mpz_init(this->n);
    mpz_set_str(this->n, "0", 10);

    mpz_init(this->e);
    mpz_set_str(this->e, "65537", 10);
}

PrivKey::~PrivKey()
{
    mpz_clear(this->p);
    mpz_clear(this->q);
    mpz_clear(this->d);
    mpz_clear(this->n);
    mpz_clear(this->e);
}

void PrivKey::get_rand_prime(mpz_t &prime, const uint32_t nbits)
{
    const uint8_t rem = nbits & 0x07;
    const uint32_t BUFFER_SIZE = (nbits >> 3) + bool(rem);
    uint8_t *temp_buf = new uint8_t[BUFFER_SIZE];

    do
    {
        for (uint32_t i = 0; i < BUFFER_SIZE; i++)
            temp_buf[i] = std::rand() & 0xff;
        
        if (rem == 0)
            temp_buf[BUFFER_SIZE - 1] |= (1 << 7);
        else
        {
            temp_buf[BUFFER_SIZE - 1] &= (1 << rem) - 1;
            temp_buf[BUFFER_SIZE - 1] |= 1 << (rem - 1);
        }

        temp_buf[0] |= 0x01;

        mpz_t temp; mpz_init(temp);
        mpz_import(temp, BUFFER_SIZE, 1, sizeof(temp_buf[0]), 0, 0, temp_buf);

        mpz_nextprime(prime, temp);
        mpz_clear(temp);
    }
    while (mpz_sizeinbase(prime, 2) != nbits);

    delete[] temp_buf;
}

void PrivKey::random(const uint32_t p_bits, const uint32_t q_bits)
{
    this->get_rand_prime(this->p, p_bits);
    this->get_rand_prime(this->q, q_bits);

    mpz_mul(this->n, this->p, this->q);

    mpz_t phi_p; mpz_init(phi_p);
    mpz_sub_ui(phi_p, this->p, 1);

    mpz_t phi; mpz_init(phi);
    mpz_sub_ui(phi, this->q, 1);
    mpz_mul(phi, phi, phi_p);

    mpz_invert(this->d, this->e, phi);

    mpz_clear(phi_p);
    mpz_clear(phi);
}

PubKey::PubKey(void)
{
    mpz_init(this->n);
    mpz_set_str(this->n, "0", 10);

    mpz_init(this->e);
    mpz_set_str(this->e, "65537", 10);
}

PubKey::PubKey(const PrivKey &key)
{
    mpz_init(this->n);
    mpz_mul(this->n, key.p, key.q);

    mpz_init(this->e);
    mpz_set_str(this->e, "65537", 10);
}

PubKey::~PubKey()
{
    mpz_clear(this->n);
    mpz_clear(this->e);
}

void PubKey::construct(const PrivKey &key)
{
    mpz_mul(this->n, key.p, key.q);
}

void RSA::encrypt(mpz_t &ct, const mpz_t &pt, const PrivKey &key) const
{
    if (mpz_cmp(pt, key.n) >= 0) invalid_pt_exc();

    mpz_powm(ct, pt, key.d, key.n);
}

void RSA::encrypt(mpz_t &ct, const mpz_t &pt, const PubKey &key) const
{
    if (mpz_cmp(pt, key.n) >= 0) invalid_pt_exc();

    mpz_powm(ct, pt, key.e, key.n);
}

void RSA::decrypt(mpz_t &pt, const mpz_t &ct, const PrivKey &key) const
{
    if (mpz_cmp(ct, key.n) >= 0) invalid_ct_exc();

    mpz_powm(pt, ct, key.d, key.n);
}

void RSA::decrypt(mpz_t &pt, const mpz_t &ct, const PubKey &key) const
{
    if (mpz_cmp(ct, key.n) >= 0) invalid_ct_exc();

    mpz_powm(pt, ct, key.e, key.n);
}

std::tuple<uint8_t *, uint32_t> RSA::encrypt(void *dest, const void *ptbuf, uint32_t n_bytes, const PrivKey &key) const
{
    const uint8_t *ptbuf_ = (const uint8_t*)ptbuf;

    mpz_t pt; mpz_init(pt);
    mpz_t ct; mpz_init(ct);

    if (ptbuf) mpz_import(pt, n_bytes, 1, sizeof(ptbuf_[0]), 0, 0, ptbuf_);
    else mpz_set_str(pt, "0", 10);

    try
    {
        this->encrypt(ct, pt, key);
    }
    catch (const std::exception &exc)
    {
        mpz_clear(pt);
        mpz_clear(ct);

        throw exc;
    }

    uint32_t numb = sizeof(ptbuf_[0]) << 3;
    uint32_t ct_n_bytes = (mpz_sizeinbase(ct, 2) + numb - 1) / numb;

    if (dest) dest = std::realloc(dest, ct_n_bytes);
    else dest = std::malloc(ct_n_bytes);

    mpz_export(dest, nullptr, 1, sizeof(ptbuf_[0]), 1, 0, ct);

    mpz_clear(pt);
    mpz_clear(ct);

    return std::tuple<uint8_t *, uint32_t>((uint8_t *)dest, ct_n_bytes);
}

std::tuple<uint8_t *, uint32_t> RSA::encrypt(void *dest, const void *ptbuf, uint32_t n_bytes, const PubKey &key) const
{
    const uint8_t *ptbuf_ = (const uint8_t*)ptbuf;

    mpz_t pt; mpz_init(pt);
    mpz_t ct; mpz_init(ct);

    if (ptbuf) mpz_import(pt, n_bytes, 1, sizeof(ptbuf_[0]), 0, 0, ptbuf_);
    else mpz_set_str(pt, "0", 10);

    try
    {
        this->encrypt(ct, pt, key);
    }
    catch (const std::exception &exc)
    {
        mpz_clear(pt);
        mpz_clear(ct);

        throw exc;
    }

    uint32_t numb = sizeof(ptbuf_[0]) << 3;
    uint32_t ct_n_bytes = (mpz_sizeinbase(ct, 2) + numb - 1) / numb;

    if (dest) dest = std::realloc(dest, ct_n_bytes);
    else dest = std::malloc(ct_n_bytes);

    mpz_export(dest, nullptr, 1, sizeof(ptbuf_[0]), 1, 0, ct);

    mpz_clear(pt);
    mpz_clear(ct);

    return std::tuple<uint8_t *, uint32_t>((uint8_t *)dest, ct_n_bytes);
}

std::tuple<uint8_t *, uint32_t> RSA::decrypt(void *dest, const void *ctbuf, uint32_t n_bytes, const PrivKey &key) const
{
    const uint8_t *ctbuf_ = (const uint8_t*)ctbuf;

    mpz_t ct; mpz_init(ct);
    mpz_t pt; mpz_init(pt);

    if (ctbuf) mpz_import(ct, n_bytes, 1, sizeof(ctbuf_[0]), 0, 0, ctbuf_);
    else mpz_set_str(ct, "0", 10);

    try
    {
        this->decrypt(pt, ct, key);
    }
    catch (const std::exception &exc)
    {
        mpz_clear(ct);
        mpz_clear(pt);

        throw exc;
    }

    uint32_t numb = sizeof(ctbuf_[0]) << 3;
    uint32_t pt_n_bytes = (mpz_sizeinbase(pt, 2) + numb - 1) / numb;

    if (dest) dest = std::realloc(dest, pt_n_bytes);
    else dest = std::malloc(pt_n_bytes);

    mpz_export(dest, nullptr, 1, sizeof(ctbuf_[0]), 1, 0, pt);

    mpz_clear(pt);
    mpz_clear(ct);

    return std::tuple<uint8_t *, uint32_t>((uint8_t *)dest, pt_n_bytes);
}

std::tuple<uint8_t *, uint32_t> RSA::decrypt(void *dest, const void *ctbuf, uint32_t n_bytes, const PubKey &key) const
{
    const uint8_t *ctbuf_ = (const uint8_t*)ctbuf;

    mpz_t ct; mpz_init(ct);
    mpz_t pt; mpz_init(pt);

    if (ctbuf) mpz_import(ct, n_bytes, 1, sizeof(ctbuf_[0]), 0, 0, ctbuf_);
    else mpz_set_str(ct, "0", 10);

    try
    {
        this->decrypt(pt, ct, key);
    }
    catch (const std::exception &exc)
    {
        mpz_clear(ct);
        mpz_clear(pt);

        throw exc;
    }

    uint32_t numb = sizeof(ctbuf_[0]) << 3;
    uint32_t pt_n_bytes = (mpz_sizeinbase(pt, 2) + numb - 1) / numb;

    if (dest) dest = std::realloc(dest, pt_n_bytes);
    else dest = std::malloc(pt_n_bytes);

    mpz_export(dest, nullptr, 1, sizeof(ctbuf_[0]), 1, 0, pt);

    mpz_clear(pt);
    mpz_clear(ct);

    return std::tuple<uint8_t *, uint32_t>((uint8_t *)dest, pt_n_bytes);
}
