#ifndef RSA_1
#define RSA_1

#include <cstdint>
#include <random>
#include <string>
#include <fmt/core.h>
#include <gmpxx.h>


using Key = std::pair<mpz_class, mpz_class>;

class RSA
{ 

public:

    enum KeyType
    {
        PUBLIC,
        PRIVATE
    };

    RSA(const mpz_class& p, const mpz_class& q);

    auto crack_private_key(const Key& other_public_key) const noexcept -> Key;

    auto get_key(const KeyType type) const noexcept-> std::string;

    auto is_valid() const noexcept -> bool;

    ~RSA() = default;

public:
    Key public_key;


private:
    auto get_random_prime(std::mt19937& rng) noexcept -> mpz_class;

    auto is_prime(const mpz_class& n) noexcept -> bool;

private:
    mpz_class n;
    mpz_class pi_n;
    mpz_class e;
    mpz_class d;
    bool is_pq_valid;
    Key private_key;
};

#endif