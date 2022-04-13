#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <cmath>
#include "spn.h"

std::string bytes_to_hex(const std::vector<uint32_t> &vec, uint32_t width)
{
    std::stringstream ss;

    for (const uint32_t &num: vec)
        ss << std::setfill('0') << std::setw(width) << std::hex << (num | 0);
    
    return ss.str();
}

bool linear_cryptanalysis(void)
{
    const SPN spn;

    // build table of input values
    std::vector<uint32_t> sbox_in;
    for (uint32_t i = 0; i < 0x10; i++)
        sbox_in.push_back(i);

    // build table of output values
    std::vector<uint32_t> sbox_out;
    for (const uint32_t &seq: sbox_in)
        sbox_out.push_back(spn.sbox.at(seq));

    // build an ordered map between input and output values
    std::vector<std::pair<uint32_t, uint32_t>> sbox_b;
    for (uint32_t i = 0; i < sbox_in.size(); i++)
        sbox_b.push_back(std::pair<uint32_t, uint32_t>(sbox_in[i], sbox_out[i]));

    // initialise the linear approximation table (LAT)
    std::vector<std::vector<uint32_t>> prob_bias;
    for (uint32_t i = 0; i < sbox_b.size(); i++)
        prob_bias.push_back(std::vector<uint32_t>(sbox_b.size(), 0));
    
    /* a complete enumeration of all the linear approximations of the simple SPN
    cipher s-box. dividing an element value by 16 gives the probability bias 
    for the particular linear combination of input and output bits.
    */

    std::cout << "linear approximation table for a basic SPN cipher's sbox:\n";
    std::cout << "(x-axis: output equation - 8, y-axis: input equation - 8)\n\n";

    for (const std::pair<uint32_t, uint32_t> &num: sbox_b)
    {
        uint32_t inp_num = num.first;
        uint32_t out_num = num.second;

        std::vector<uint32_t> x(4), y(4);

        for (uint32_t i = 0; i < 4; i++)
        {
            x[3 - i] = inp_num & 1;
            y[3 - i] = out_num & 1;
            inp_num >>= 1;
            out_num >>= 1;
        }

        std::vector<uint32_t> eqn_in {
            0, x[3], x[2], x[2]^x[3],
            x[1], x[1]^x[3], x[1]^x[2], x[1]^x[2]^x[3],
            x[0], x[0]^x[3], x[0]^x[2], x[0]^x[2]^x[3],
            x[0]^x[1], x[0]^x[1]^x[3], x[0]^x[1]^x[2], x[0]^x[1]^x[2]^x[3]
        };

        std::vector<uint32_t> eqn_out {
            0, y[3], y[2], y[2]^y[3],
            y[1], y[1]^y[3], y[1]^y[2], y[1]^y[2]^y[3],
            y[0], y[0]^y[3], y[0]^y[2], y[0]^y[2]^y[3],
            y[0]^y[1], y[0]^y[1]^y[3], y[0]^y[1]^y[2], y[0]^y[1]^y[2]^y[3]
        };

        for (uint32_t x_idx = 0; x_idx < eqn_in.size(); x_idx++)
        {
            for (uint32_t y_idx = 0; y_idx < eqn_out.size(); y_idx++)
            {
                if (eqn_in[x_idx] == eqn_out[y_idx])
                    prob_bias[x_idx][y_idx] += 1;
            }
        }
    }

    // print the linear approximation table
    for (const std::vector<uint32_t> &bias: prob_bias)
    {
        for (const int32_t bia: bias)
        {
            std::cout << std::setfill('0') << std::setw(2);
            std::cout << std::dec << (bia - 8) << "  ";
        }
        std::cout << "\n";
    }

    /*
    constructing linear approximations for the complete cipher.
    it is possible to attack the cipher by recovering a subset of the subkey
    bits that follow the last round.

    using the LAT, we can construct the following equation that holds with 
    probability 0.75. let U_{i} and V_{i} represent the 16-bit block of bits
    at the input and output of the round i s-boxes, respectively, and let 
    K_{i,j} represent the j'th bit of the subkey block of bits exclusive-ORed
    at the input to round i. Also let P_{i} represent the i'th input bit, then

    U_{4,6} ⊕ U_{4,8} ⊕ U_{4,14} ⊕ U_{4,16} ⊕ P_{5} ⊕ P_{7} ⊕ P_{8} ⊕ SUM(K) = 0 where

    SUM(K) = K_{1,5} ⊕ K_{1,7} ⊕ K_{1,8} ⊕ K_{2,6} ⊕ K_{3,6} ⊕ K_{3,14} ⊕ K_{4,6} ⊕ K_{4,8} ⊕ K_{4,14} ⊕ K_{4,16}
    holds with a probability of 15/32 (with a bias of 1/32). 

    since sum(K) is fixed (by the key, k), U_{4,6}⊕U_{4,8}⊕U_{4,14}⊕U_{4,16}⊕P_{5}⊕P_{7}⊕P_{8} = 0
    must hold with a probability of either 15/32 or 1-15/32. In other words we
    now have a linear approximation of the first three rounds of the cipher with
    a bias of magnitude 1/32.
    */

    std::vector<uint32_t> key = spn.get_rand_key();

    uint32_t k_5 = 0, k_5_5_8, k_5_13_16;
    uint32_t shift = (key.size() - 1) << 3;

    for (const uint32_t byte: key)
    {
        k_5 <<= 8;
        k_5 += byte;
    }

    k_5 &= 0xffff; // the last 16 bits are K5
    k_5_5_8 = (k_5 >> 8) & 0xf;
    k_5_13_16 = k_5 & 0xf;

    std::cout << "\ntest key: " << bytes_to_hex(key, 2) << " ";
    std::cout << "(k_5 = 0x" << bytes_to_hex({k_5}, 4) << ")\n";
    std::cout << "target partial sub_key K_5,5...k_5,8 = 0x" << bytes_to_hex({k_5_5_8}, 1) << "\n";
    std::cout << "target partial sub_key K_5,13...k_5,16 = 0x" << bytes_to_hex({k_5_13_16}, 1) << "\n\n";
    std::cout << "testing each target sub_key value ...\n";

    std::vector<uint32_t> count_target_bias(256, 0);

    for (uint32_t pt = 0; pt < 10000; pt++)
    {
        uint32_t ct = *(spn.encrypt({pt}, key).begin());
        uint32_t ct_5_8 = (ct >> 8) & 0xf;
        uint32_t ct_13_16 = ct & 0xf;

        /*
        for each target partial subkey value k_5 | k_8 | k_13 | k_16 in [0,255],
        increment the count whenever equation (5) holds true
        */

        for (uint32_t target = 0; target < 256; target++)
        {
            uint32_t target_5_8 = (target >> 4) & 0xf;
            uint32_t target_13_16 = target & 0xf;
            uint32_t v_5_8 = ct_5_8 ^ target_5_8;
            uint32_t v_13_16 = ct_13_16 ^ target_13_16;

            uint32_t u_5_8 = spn.inv_sbox.at(v_5_8);
            uint32_t u_13_16 = spn.inv_sbox.at(v_13_16);

            uint32_t l_approx = ((u_5_8 >> 2) & 0x1) ^ (u_5_8 & 0x1);
            l_approx ^= ((u_13_16 >> 2) & 0x1) ^ (u_13_16 & 0x1);
            l_approx ^= ((pt >> 11) & 0x1) ^ ((pt >> 9) & 0x1) ^ ((pt >> 8) & 0x1);

            if (l_approx == 0) count_target_bias[target]++;
        }
    }

    /*
    the count which deviates the largest from half of the number of
    plaintext/ciphertext samples is assumed to be the correct value.
    */

    std::vector<double> bias;
    for (const uint32_t &l_approx: count_target_bias)
    {
        double laprx = static_cast<double>(l_approx);
        laprx = fabs(laprx - 5000.0);
        laprx /= 10000.0;
        bias.push_back(laprx);
    }

    double max_res = 0.0;
    uint32_t r_idx, max_idx;
    r_idx = max_idx = 0;

    for (const double &res: bias)
    {
        if (res > max_res)
        {
            max_res = res;
            max_idx = r_idx;
        }

        r_idx++;
    }

    std::cout << "Highest bias is " << max_res << " ";
    std::cout << "for sub_key value 0x" << bytes_to_hex({max_idx}, 2) << "\n\n";

    return (
        (((max_idx >> 4) & 0xf) == k_5_5_8)
        and ((max_idx & 0xf) == k_5_13_16)
    );
}

int main(void)
{
    linear_cryptanalysis()
        ? std::cout << "Success!\n"
        : std::cout << "Failure\n";

    return 0;
}
