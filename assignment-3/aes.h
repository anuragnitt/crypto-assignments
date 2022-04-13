#include <vector>
#include <cstdlib>
#include <cstring>
#include <tuple>

static void invalid_pad_exc(void)
{
    throw std::runtime_error("invalid padding");
}

static void invalid_key_exc(void)
{
    throw std::runtime_error("invalid key length");
}

class PKCS7
{
    public:

        bool check_padding(const void *, uint32_t, uint32_t) const;
        std::tuple<uint8_t *, uint32_t> pad(void *, const void *, uint32_t, uint32_t) const;
        std::tuple<uint8_t *, uint32_t> unpad(void *, const void *, uint32_t, uint32_t) const;
};

class AES
{
    private:

        std::tuple<uint8_t *, uint32_t> xor_bufs(uint8_t *, const uint8_t *, uint32_t, const uint8_t *, uint32_t) const;

        void substitute_bytes(uint8_t *, uint32_t, bool) const;
        void rot_bytes(uint8_t *, uint32_t, uint32_t, bool) const;
        void shift_rows(uint8_t *, bool) const;

        uint8_t galois_field_mul(uint8_t, uint8_t) const;
        void mix_columns(uint8_t *, bool) const;

        std::tuple<uint8_t *, uint32_t> expand_key(uint8_t *, const uint8_t *, uint32_t) const;
        void get_round_key(uint8_t *, const uint8_t *, uint32_t) const;
        void add_round_key(const uint8_t *, uint8_t *) const;

        void rijndael(uint8_t *, const uint8_t *, uint32_t) const;
        void inv_rijndael(uint8_t *, const uint8_t *, uint32_t) const;

    public:

        const uint32_t block_size;
        const std::vector<uint8_t> sbox;
        const std::vector<uint8_t> inv_sbox;

        AES(void);

        std::tuple<uint8_t *, uint32_t> encrypt(void *, const void *, uint32_t, const void *, uint32_t, const void *) const;
        std::tuple<uint8_t *, uint32_t> decrypt(void *, const void *, uint32_t, const void *, uint32_t, const void *) const;
};

AES::AES(void)
    : block_size(16), sbox({
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    }), inv_sbox ({
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    }) {}

bool PKCS7::check_padding(const void *buffer, uint32_t n_bytes, uint32_t block_size) const
{
    if (!buffer or (n_bytes == 0)) invalid_pad_exc();

    if (n_bytes % block_size) return true;

    uint8_t *buffer_ = (uint8_t *)buffer;
    uint32_t pad_byte = buffer_[n_bytes - 1];

    if (n_bytes <= pad_byte) return true;

    for (uint32_t i = n_bytes - pad_byte; i < n_bytes; i++)
        if (buffer_[i] != pad_byte) return true;
    
    return false;
}

std::tuple<uint8_t *, uint32_t> PKCS7::pad(void *dest, const void *buffer, uint32_t n_bytes, uint32_t block_size) const
{
    if (!buffer or (n_bytes == 0)) invalid_pad_exc();

    uint32_t pad_byte = block_size;
    pad_byte -= n_bytes % block_size;

    const uint8_t *buffer_ = (const uint8_t *)buffer;
    uint32_t new_size = n_bytes + pad_byte;

    if (dest) dest = std::realloc(dest, new_size);
    else dest = std::malloc(new_size);

    if (dest != buffer) std::memcpy(dest, buffer, n_bytes);

    uint8_t *dest_ = (uint8_t *)dest;
    std::memset((void *)(dest_ + n_bytes), pad_byte, pad_byte);

    return std::tuple<uint8_t *, uint32_t>(dest_, new_size);
}

std::tuple<uint8_t *, uint32_t> PKCS7::unpad(void *dest, const void *buffer, uint32_t n_bytes, uint32_t block_size) const
{
    if (this->check_padding(buffer, n_bytes, block_size)) invalid_pad_exc();

    const uint8_t *buffer_ = (const uint8_t *)buffer;
    uint32_t pad_byte = buffer_[n_bytes - 1];
    uint32_t new_size = n_bytes - pad_byte;

    if (dest) dest = std::realloc(dest, new_size);
    else dest = std::malloc(new_size);

    if (dest != buffer) std::memcpy(dest, buffer, new_size);

    return std::tuple<uint8_t *, uint32_t>((uint8_t *)dest, new_size);
}

std::tuple<uint8_t *, uint32_t> AES::xor_bufs(uint8_t *dest, const uint8_t *bytes_1, uint32_t n_bytes_1, const uint8_t *bytes_2, uint32_t n_bytes_2) const
{
    uint32_t out_n_bytes = std::max(n_bytes_1, n_bytes_2);
    uint8_t *out_bytes = nullptr;

    if (dest) out_bytes = (uint8_t*)dest;
    else out_bytes = new uint8_t[out_n_bytes];

    if (n_bytes_1 <= n_bytes_2)
    {
        for (uint32_t i = 0; i < n_bytes_1; i++) out_bytes[i] = bytes_1[i] ^ bytes_2[i];
        std::memcpy((void *)(out_bytes + n_bytes_1), (void *)(bytes_2 + n_bytes_1), (n_bytes_2 - n_bytes_1));
    }
    else
    {
        for (uint32_t i = 0; i < n_bytes_2; i++) out_bytes[i] = bytes_1[i] ^ bytes_2[i];
        std::memcpy((void *)(out_bytes + n_bytes_2), (void *)(bytes_1 + n_bytes_2), (n_bytes_1 - n_bytes_2));
    }

    return std::tuple<uint8_t *, uint32_t>(out_bytes, out_n_bytes);
}

void AES::substitute_bytes(uint8_t *bytes, uint32_t n_bytes, bool inv) const
{
    for (uint32_t i = 0; i < n_bytes; i++)
    {
        if (inv) bytes[i] = this->inv_sbox.at(bytes[i]);
        else bytes[i] = this->sbox.at(bytes[i]);
    }
}

void AES::rot_bytes(uint8_t *bytes, uint32_t n_bytes, uint32_t shift, bool inv) const
{
    shift = shift % n_bytes;
    if (shift == 0) return;

    uint8_t *temp_buf = nullptr;

    if (
        (!inv and (shift <= (n_bytes >> 1))) or
        (inv and (shift > (n_bytes >> 1)))
    )
    {
        if (inv) shift = n_bytes - shift;
        temp_buf = new uint8_t[shift];

        std::memcpy((void *)temp_buf, (void *)bytes, shift);
        for (uint32_t i = 0; i < n_bytes - shift; i++)
            bytes[i] = bytes[i + shift];
        std::memcpy((void *)(bytes + n_bytes - shift), (void *)temp_buf, shift);
    }
    else
    {
        if (!inv) shift = n_bytes - shift;
        temp_buf = new uint8_t[shift];

        std::memcpy((void *)temp_buf, (void *)(bytes + n_bytes - shift), shift);
        for (uint32_t i = n_bytes - 1; i >= shift; i--)
            bytes[i] = bytes[i - shift];
        std::memcpy((void *)bytes, (void *)temp_buf, shift);
    }

    delete[] temp_buf;
}

void AES::shift_rows(uint8_t *block, bool inv) const
{
    for (uint32_t i = 0; i < 4; i++)
    {
        block += i * 4;
        this->rot_bytes(block, 4, i, inv);
    }
}

uint8_t AES::galois_field_mul(uint8_t x, uint8_t y) const
{
    uint8_t t = 0, z;

    for (uint8_t i = 0; i < 8; i++)
    {
        if (y & 1) t ^= x;

        z = x & 0x80;
        x <<= 1;
        x &= 0xff;

        if (z) x ^= 0x1b;
        y >>= 1;
    }

    return t;
}

void AES::mix_columns(uint8_t *block, bool inv) const
{
    uint8_t factor[4] = {2, 1, 1, 3};
    uint8_t col[4], temp[4];

    if (inv)
    {
        factor[0] = 14;
        factor[1] = 9;
        factor[2] = 13;
        factor[3] = 11;
    }


    for (uint32_t i = 0; i < 4; i++)
    {
        for (uint32_t j = 0; j < 4; j++)
            col[j] = block[i + j*4];

        std::memcpy((void *)temp, (void *)col, 4);

        for (uint32_t j = 0; j < 4; j++)
        {
            col[j] = 0;
            for (uint32_t k = 0; k < 4; k++)
                col[j] ^= this->galois_field_mul(temp[(j + k*3) & 0x03], factor[k]);
        }
    }
}

std::tuple<uint8_t *, uint32_t> AES::expand_key(uint8_t *dest, const uint8_t *key, uint32_t n_bytes) const
{
    if ((n_bytes < this->block_size) or (n_bytes & 0x07))
        invalid_key_exc();

    uint32_t n_words = n_bytes >> 2;
    uint32_t n_rkeys = n_words + 7;
    uint32_t n_rounds = n_rkeys << 2;
    uint32_t exp_key_size = n_rounds << 2;

    uint8_t rc[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};
    uint8_t rcon[10][4];

    for (uint32_t i = 0; i < sizeof(rc) / sizeof(rc[0]); i++)
    {
        for (uint32_t j = 0; j < 4; j++)
        {
            if (j) rcon[i][j] = 0;
            else rcon[i][j] = rc[i];
        }
    }

    if (dest) dest = (uint8_t *)std::realloc(dest, exp_key_size);
    else dest = new uint8_t[exp_key_size];
    uint8_t *exp_key = dest;

    for (uint32_t i = 0; i < n_rounds; i++)
    {
        if (i < n_words)
            std::memcpy((void *)exp_key, (void *)(key + i*4), 4);
        else
        {
            std::memcpy((void *)exp_key, (void *)(exp_key - 4), 4);

            if ((i >= n_words) and (i % n_words == 0))
            {
                this->rot_bytes(exp_key, 4, 1, false);
                this->substitute_bytes(exp_key, 4, false);
                this->xor_bufs(exp_key, exp_key, 4, exp_key - (n_words << 2), 4);
                this->xor_bufs(exp_key, exp_key, 4, rcon[(i / n_words) - 1], 4);
            }
            else if ((i >= n_words) and (n_words > 6) and (i % n_words == 4))
            {
                this->substitute_bytes(exp_key, 4, false);
                this->xor_bufs(exp_key, exp_key, 4, exp_key - (n_words << 2), 4);
            }
            else
            {
                this->xor_bufs(exp_key, exp_key, 4, exp_key - (n_words << 2), 4);
            }
        }

        exp_key += 4;
    }

    return std::tuple<uint8_t *, uint32_t>(dest, exp_key_size);
}

void AES::get_round_key(uint8_t *rkey, const uint8_t *expanded_key, uint32_t offset) const
{
    for (uint32_t i = 0; i < 4; i++)
    {
        for (uint32_t j = 0; j < 4; j++)
            rkey[i + j*4] = expanded_key[offset + i*4 + j];
    }
}

void AES::add_round_key(const uint8_t *rkey, uint8_t* block) const
{
    this->xor_bufs(block, block, this->block_size, rkey, this->block_size);
}

void AES::rijndael(uint8_t *pt_block, const uint8_t *expanded_key, uint32_t exp_key_bytes) const
{
    uint8_t *matrix = new uint8_t[this->block_size];
    uint8_t *rkey = new uint8_t[this->block_size];

    uint32_t n_rounds = (exp_key_bytes >> 4) - 1;

    for (uint32_t i = 0; i < 4; i++)
    {
        for (uint32_t j = 0; j < 4; j++)
            matrix[i + j*4] = pt_block[i*4 + j];
    }

    this->get_round_key(rkey, expanded_key, 0);
    this->add_round_key(rkey, matrix);

    for (uint32_t round = 0; round < n_rounds; round++)
    {
        this->substitute_bytes(matrix, this->block_size, false);
        this->shift_rows(matrix, false);
        if (round < n_rounds - 1) this->mix_columns(matrix, false);

        this->get_round_key(rkey, expanded_key, (round + 1) * this->block_size);
        this->add_round_key(rkey, matrix);
    }

    for (uint32_t i = 0; i < 4; i++)
    {
        for (uint32_t j = 0; j < 4; j++)
            pt_block[i*4 + j] = matrix[i + j*4];
    }

    delete[] matrix;
    delete[] rkey;
}

void AES::inv_rijndael(uint8_t *ct_block, const uint8_t *expanded_key, uint32_t exp_key_bytes) const
{
    uint8_t *matrix = new uint8_t[this->block_size];
    uint8_t *rkey = new uint8_t[this->block_size];

    uint32_t n_rounds = (exp_key_bytes >> 4) - 1;

    for (uint32_t i = 0; i < 4; i++)
    {
        for (uint32_t j = 0; j < 4; j++)
            matrix[i + j*4] = ct_block[i*4 + j];
    }

    for (uint32_t round = 0; round < n_rounds; round++)
    {
        this->get_round_key(rkey, expanded_key, (n_rounds - round) * this->block_size);
        this->add_round_key(rkey, matrix);

        if (round > 0) this->mix_columns(matrix, true);
        this->shift_rows(matrix, true);
        this->substitute_bytes(matrix, this->block_size, true);
    }

    this->get_round_key(rkey, expanded_key, 0);
    this->add_round_key(rkey, matrix);

    for (uint32_t i = 0; i < 4; i++)
    {
        for (uint32_t j = 0; j < 4; j++)
            ct_block[i*4 + j] = matrix[i + j*4];
    }

    delete[] rkey;
    delete[] matrix;
}

std::tuple<uint8_t *, uint32_t> AES::encrypt(void *dest, const void *pt_buf, uint32_t pt_bytes, const void *key_buf, uint32_t key_bytes, const void *iv_buf) const
{
    if (!pt_buf or (pt_bytes == 0)) invalid_pad_exc();

    if (pt_bytes % this->block_size) invalid_pad_exc();
    if ((key_bytes < this->block_size) or (key_bytes & 0x07)) invalid_key_exc();

    const uint8_t *key = (const uint8_t*)key_buf;
    const uint8_t *iv = (const uint8_t*)iv_buf;

    if (dest and (dest != pt_buf)) dest = std::realloc(dest, pt_bytes);
    else dest = std::malloc(pt_bytes);

    if (dest != pt_buf) std::memcpy(dest, pt_buf, pt_bytes);

    uint8_t *ct = (uint8_t *)dest;
    uint8_t *expanded_key;
    uint32_t exp_key_bytes;

    std::tie(expanded_key, exp_key_bytes) = this->expand_key(nullptr, key, key_bytes);

    uint32_t n_blocks = pt_bytes / this->block_size;
    uint32_t n_rounds = (key_bytes >> 2) + 6;

    for (uint32_t i = 0; i < n_blocks; i++)
    {
        this->xor_bufs(ct, ct, this->block_size, iv, this->block_size);
        this->rijndael(ct, expanded_key, exp_key_bytes);
        iv = ct;
        ct += this->block_size;
    }

    delete[] expanded_key;

    return std::tuple<uint8_t *, uint32_t>((uint8_t *)dest, pt_bytes);
}

std::tuple<uint8_t *, uint32_t> AES::decrypt(void *dest, const void *ct_buf, uint32_t ct_bytes, const void *key_buf, uint32_t key_bytes, const void *iv_buf) const
{
    if (!ct_buf or (ct_bytes == 0)) invalid_pad_exc();

    if ((key_bytes < this->block_size) or (key_bytes & 0x07)) invalid_key_exc();

    const uint8_t *key = (const uint8_t*)key_buf;
    const uint8_t *iv = (const uint8_t*)iv_buf;
    const uint8_t *ct_ = (const uint8_t*)ct_buf;

    if (dest and (dest != ct_buf)) dest = std::realloc(dest, ct_bytes);
    else dest = std::malloc(ct_bytes);

    if (dest != ct_buf) std::memcpy(dest, ct_buf, ct_bytes);

    uint8_t *pt = (uint8_t *)dest;
    uint8_t *expanded_key;
    uint32_t exp_key_bytes;

    std::tie(expanded_key, exp_key_bytes) = this->expand_key(nullptr, key, key_bytes);

    uint32_t n_blocks = ct_bytes / this->block_size;
    uint32_t n_rounds = (key_bytes >> 2) + 6;

    for (uint32_t i = 0; i < n_blocks; i++)
    {
        this->inv_rijndael(pt, expanded_key, exp_key_bytes);
        this->xor_bufs(pt, pt, this->block_size, iv, this->block_size);
        iv = ct_ + (this->block_size * i);
        pt += this->block_size;
    }

    delete[] expanded_key;

    return std::tuple<uint8_t *, uint32_t>((uint8_t *)dest, ct_bytes);
}
