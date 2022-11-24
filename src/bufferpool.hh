#pragma once

#include <array>

#include "cstdlib"

template <size_t BUFFER_SIZE, size_t COUNT>
struct BufferPool
{
    BufferPool() = default;

    char* next()
    {
        auto* next = m_pool[m_current++].data();
        m_current %= COUNT;
        return next;
    }

    size_t get_buffer_size() { return BUFFER_SIZE; }

private:
    std::array<std::array<char, BUFFER_SIZE>, COUNT> m_pool{};
    size_t m_current{0};
};