#ifndef RC4_HPP
#define RC4_HPP

#include <string>

class RC4
{
public:
    RC4(std::string_view key);

    void KSA() noexcept;

    void encrypt(uint8_t message[],  const uint64_t size) noexcept;

    void decrypt(uint8_t ciphertext[], const uint64_t size) noexcept;

    void print_state() const noexcept;

    ~RC4() = default;

private:
    void initialize_state() noexcept;

    void swap_state_values(const uint8_t i, const uint8_t j) noexcept;

private:
    std::string m_key;
    uint64_t m_key_size;
    uint8_t m_state[256];
};

#endif