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

    // assumption -> both messages are similar
    static bool is_same_key_used_sm(uint8_t msg1[], uint8_t msg2[], const uint64_t size1, const uint64_t size2) noexcept;

    // assumption -> messeges might be different
    static bool is_same_key_used_dm(uint8_t msg1[], uint8_t msg2[], const uint64_t size1, const uint64_t size2) noexcept;

    static void show_hex_rep(uint8_t msg[], const uint64_t size) noexcept;

    ~RC4() = default;

private:
    void initialize_state() noexcept;

    void swap_state_values(const uint64_t i, const uint64_t j) noexcept;

private:
    std::string m_key;
    uint64_t m_key_size;
    uint8_t m_state[256];
};

#endif