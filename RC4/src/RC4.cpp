#include "RC4.hpp"
#include <fmt/core.h>
#include <fmt/ranges.h>


// #define DEBUG

RC4::RC4(std::string_view key)
    : m_key {key}, m_key_size {key.size()}, m_state{}
{}

void RC4::KSA() noexcept
{
    initialize_state();

    #ifdef DEBUG
        print_state();
    #endif

    uint8_t T[256];

    for (int i {0}; i < 256; ++i)
    {
        T[i] = m_key[i % m_key_size];
    }

    // permutate state using m_key
    int j {0};
    for (int i {0}; i < 256; ++i)
    {
        j = (j + m_state[i] + T[i]) % 256;
        swap_state_values(i, j); 
    }

    #ifdef DEBUG
        print_state();  
    #endif
}

void RC4::encrypt(uint8_t message[], const uint64_t message_size) noexcept
{
    // initialize and permutate state
    KSA();

    uint64_t i {0};
    uint64_t j {0};

    for (int idx {0}; idx < message_size - 1; ++idx) // message_size - 1, since we don't wanna touch '\0'
    {
        i = (i + 1) % 256;
        j = (j + m_state[i]) % 256;

        swap_state_values(i, j);

        // encrypt corresponding byte
        message[idx] ^= m_state[( m_state[i] + m_state[j] ) % 256];
    }

}

void RC4::decrypt(uint8_t ciphertext[], const uint64_t size) noexcept
{
    // since we're dealing with symetric crypto (same key for encryption / decryption)
    encrypt(ciphertext, size);
}

void RC4::print_state() const noexcept
{
    fmt::print("STATE: {}\n", m_state);
}

void RC4::initialize_state() noexcept
{
    // create initial state ( uint8_t from 0 .. 255)
    for (int i {0}; i < 256; ++i)
    {
        m_state[i] = i;
    }
}

void RC4::swap_state_values(const uint64_t i, const uint64_t j) noexcept
{
    const uint64_t temp {m_state[i]};
    m_state[i] = m_state[j];
    m_state[j] = temp;
}
