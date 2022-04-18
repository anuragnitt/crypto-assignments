#include "simplesocket.h"
#include "clientsocket.h"

template <typename T>
void send_data(T s, const void *src, uint32_t n_bytes)
{
    std::stringstream buffer;
    const uint8_t *src_ = (const uint8_t *)src;

    for (uint32_t i = 0; i < n_bytes; i++)
        buffer << std::setfill('0') << std::setw(2) << std::hex << (int)src_[i];

    *s << buffer.str();
}

template <typename T>
void * recv_data(T c, void *dest, uint32_t &n_bytes)
{
    std::string buffer;
    *c >> buffer;

    n_bytes = buffer.length() >> 1;
    if (dest) dest = std::realloc(dest, n_bytes);
    else dest = std::malloc(n_bytes);

    uint8_t *dest_ = (uint8_t *)dest;
    uint32_t i = 0; long temp;

    while (i < buffer.length())
    {
        temp = std::strtol(buffer.substr(i, 2).c_str(), nullptr, 16);
        dest_[i >> 1] = temp & 0xff;
        i += 2;
    }

    return dest;
}
