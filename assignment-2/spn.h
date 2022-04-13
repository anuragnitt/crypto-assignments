#include <vector>
#include <map>
#include <cstdlib>
#include <ctime>

class SPN
{
    private:
        uint32_t apply_sbox(uint32_t, bool) const;
        std::vector<uint32_t> get_sub_keys(const std::vector<uint32_t> &) const;

    public:
        const uint32_t block_size, key_size, rounds;
        const std::map<uint32_t, uint32_t> sbox;
        const std::map<uint32_t, uint32_t> inv_sbox;
        const std::map<uint32_t, uint32_t> pbox;

        SPN(void);
        std::vector<uint32_t> get_rand_key(void) const;
        std::vector<uint32_t> encrypt(const std::vector<uint32_t>, std::vector<uint32_t> &) const;
        std::vector<uint32_t> decrypt(const std::vector<uint32_t>, std::vector<uint32_t> &) const;
};

SPN::SPN(void)
    : block_size(16), key_size(10), rounds(3), sbox({
        {0x0, 0xe}, {0x1, 0x4}, {0x2, 0xd}, {0x3, 0x1},
        {0x4, 0x2}, {0x5, 0xf}, {0x6, 0xb}, {0x7, 0x8},
        {0x8, 0x3}, {0x9, 0xa}, {0xa, 0x6}, {0xb, 0xc},
        {0xc, 0x5}, {0xd, 0x9}, {0xe, 0x0}, {0xf, 0x7}
    }), inv_sbox({
        {0xe, 0x0}, {0x4, 0x1}, {0xd, 0x2}, {0x1, 0x3},
        {0x2, 0x4}, {0xf, 0x5}, {0xb, 0x6}, {0x8, 0x7},
        {0x3, 0x8}, {0xa, 0x9}, {0x6, 0xa}, {0xc, 0xb},
        {0x5, 0xc}, {0x9, 0xd}, {0x0, 0xe}, {0x7, 0xf}
    }), pbox({
        {0x0, 0x0}, {0x1, 0x4}, {0x2, 0x8}, {0x3, 0xc},
        {0x4, 0x1}, {0x5, 0x5}, {0x6, 0x9}, {0x7, 0xd},
        {0x8, 0x2}, {0x9, 0x6}, {0xa, 0xa}, {0xb, 0xe},
        {0xc, 0x3}, {0xd, 0x7}, {0xe, 0xb}, {0xf, 0xf}
    }) {}

std::vector<uint32_t> SPN::get_rand_key(void) const
{
    std::vector<uint32_t> key(this->key_size, 0);
    std::srand(static_cast<uint32_t>(std::time(nullptr)));

    for (uint32_t i = 0; i < this->key_size; i++)
        key[i] = abs(static_cast<uint32_t>(std::rand())) & 0xff;
    
    return key;
}

uint32_t SPN::apply_sbox(uint32_t state, bool inv) const
{
    std::vector<uint32_t> sub_states {
        (state & 0x000f),
        (state & 0x00f0) >> 4,
        (state & 0x0f00) >> 8,
        (state & 0xf000) >> 12
    };

    uint32_t index = 0;

    for (const uint32_t &sub_state: sub_states)
    {
        if (inv) sub_states[index] = this->inv_sbox.at(sub_state);
        else sub_states[index] = this->sbox.at(sub_state);
        index++;
    }

    uint32_t new_state = 0, shift = 0;

    for (const uint32_t &sub_state: sub_states)
    {
        new_state |= (sub_state << shift);
        shift += 4;
    }

    return new_state;
}

std::vector<uint32_t> SPN::get_sub_keys(const std::vector<uint32_t> &key) const
{
    std::vector<uint32_t> sub_keys;

    {
        uint32_t key_idx = 0;
        uint32_t sub_key;

        while (key_idx < key.size())
        {
            sub_key = key[key_idx];
            sub_key <<= 8;
            sub_key += key[key_idx + 1];

            sub_keys.push_back(sub_key);
            key_idx += 2;
        }
    }

    return sub_keys;
}

std::vector<uint32_t> SPN::encrypt(const std::vector<uint32_t> pt, std::vector<uint32_t> &key) const
{
    std::vector<uint32_t> sub_keys = this->get_sub_keys(key);

    std::vector<uint32_t> ct;
    uint32_t state_temp, bit_idx;

    for (uint32_t state: pt)
    {
        // first three rounds of sinple SPN cipher
        for (uint32_t rnum = 0; rnum < this->rounds; rnum++)
        {
            // XOR state with round key (3, subkeys 1, ..., 4)
            state ^= sub_keys[rnum];

            // break state into nibbles, perform sbox on each nibble, write to state (1)
            state = this->apply_sbox(state, false);

            // permute the state bitwise (2)
            state_temp = bit_idx = 0;
            while (bit_idx < this->block_size)
            {
                if (state & (1 << bit_idx))
                {
                    state_temp |= (1 << this->pbox.at(bit_idx));
                }

                bit_idx++;
            }

            state = state_temp;
        }

        // final round of SPN cipher (k4, sbox, s5)
        state ^= *(sub_keys.rbegin() + 1); // penultimate subkey (key 4) mixing
        state = this->apply_sbox(state, false);
        state ^= *(sub_keys.rbegin()); // final subkey (key 5) mixing

        ct.push_back(state);
    }

    return ct;
}

// simple SPN cipher decrypt function
std::vector<uint32_t> SPN::decrypt(const std::vector<uint32_t> ct, std::vector<uint32_t> &key) const
{
    // derive round keys
    std::vector<uint32_t> sub_keys = this->get_sub_keys(key);

    std::vector<uint32_t> pt;
    uint32_t state_temp, bit_idx;

    for (uint32_t state: ct)
    {
        // undo final round key
        state ^= *(sub_keys.rbegin());

        // apply inverse sbox
        state = this->apply_sbox(state, true);

        // undo first three rounds of simple SPN cipher
        for (uint32_t rnum = 0; rnum < this->rounds; rnum++)
        {
            // XOR state with round key (3, subkeys 4, ..., 0)
            state ^= sub_keys[this->rounds - rnum];

            // un-permute the state bitwise (2)
            state_temp = bit_idx = 0;
            while (bit_idx < this->block_size)
            {
                if (state & (1 << bit_idx))
                {
                    state_temp |= (1 << pbox.at(bit_idx));
                }

                bit_idx++;
            }

            state = state_temp;

            // apply inverse s-box
            state = this->apply_sbox(state, true);
        }

        // XOR state with round key 0
        state ^= *(sub_keys.begin());
        pt.push_back(state);
    }

    return pt;
}
