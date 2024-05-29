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

bool RC4::is_same_key_used_sm(uint8_t msg1[], uint8_t msg2[], const uint64_t size1, const uint64_t size2) noexcept
{
    uint64_t min_size {size1 < size2 ? size1 : size2};
    uint8_t* xor_result { new uint8_t[min_size]};

    // perform XOR on msg1 and msg2 bytes
    for (size_t i {0}; i < min_size - 1; ++i)
    {
        xor_result[i] = msg1[i] ^ msg2[i];
    }

    fmt::print("First Cipher ");
    RC4::show_hex_rep(msg1, size1);
    
    fmt::print("Second Cipher ");
    RC4::show_hex_rep(msg2, size2);

    fmt::print("XOR ");
    RC4::show_hex_rep(xor_result, min_size);

    // count '0' in XOR_RESULT
    uint64_t zeros {};
    for (size_t i {0}; i < min_size; ++i)
    {
        if (xor_result[i] == 0)
        {
            ++zeros;
        }
    }
    
    fmt::print("Zeros: {}\n", zeros);
    // if zeros / min_size (considered bytes) >> than some threshold -> return true
    float threshold {.6f};
    bool is_same_key { ( zeros / static_cast<float>(min_size) ) > threshold};
    fmt::print("RATIO: {}\n",  ( zeros / static_cast<float>(min_size)));
    
    delete[] xor_result;
      
    return is_same_key; 
}

bool RC4::is_same_key_used_dm(uint8_t msg1[], uint8_t msg2[], const uint64_t size1, const uint64_t size2) noexcept
{
    uint64_t min_size {size1 < size2 ? size1 : size2};

    uint8_t* xor_result = new uint8_t[min_size];
    
    for (size_t i {0}; i < min_size; ++i)
    {
        xor_result[i] = msg1[i] ^ msg2[i];
    }

    fmt::print("XOR ");
    RC4::show_hex_rep(xor_result, min_size);


    // 10 - NL
    // 9 - H TAb

    for (size_t i {0}; i < min_size; ++i) 
    {
        // if byte exceeds ASCII value, return false
        if (xor_result[i] >= 128 ) 
        {
            return false;
        }
    }  

    delete[] xor_result;
    return true;
}

void RC4::show_hex_rep(uint8_t msg[], uint64_t const size) noexcept
{
    fmt::print("HEX: ");
    for (int i {0}; i < size - 1; ++i)
    {
        fmt::print("{:x} ", msg[i]);
    }

    fmt::print("\n");
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
