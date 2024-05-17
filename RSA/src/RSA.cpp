#include "RSA.hpp"
#include <cstdint>
#include <random>
#include <fmt/core.h>
#include <numeric>
#include <string_view>

#define MIN_INT 3000
#define MAX_INT 100000


RSA::RSA(const mpz_class& p, const mpz_class& q)
{
    if (!is_prime(p) || !is_prime(q))
    {
        fmt::print("Provided p and q must be prime!\nAborting...\n");
        is_pq_valid = false;
        return;
    }

    is_pq_valid = true;

    fmt::println("p = {}\nq = {}\n", p.get_str(), q.get_str());
    fmt::println("Are they prime?\n{} {}", is_prime(p), is_prime(q));

    n = p * q;

    pi_n = (p - 1) * (q - 1);

    fmt::println("n = {}\npi_n = {}\n", n.get_str(), pi_n.get_str());


    std::mt19937 rng {std::random_device{}()};
    std::uniform_int_distribution<long> distribution {2, pi_n.get_si() - 1};

    do
    {
        e = mpz_class(distribution(rng));
    
    } while (gcd(e, pi_n) != 1);


    fmt::print("e = {}\n", e.get_str());

    mpz_invert(d.get_mpz_t(), e.get_mpz_t(), pi_n.get_mpz_t());

    fmt::print("d = {}\n", d.get_str());

    mpz_class gcd;
    mpz_gcd(gcd.get_mpz_t(), e.get_mpz_t(), pi_n.get_mpz_t());

    fmt::print("gcd(e, pi_n): {}\n", gcd.get_str());
    mpz_class check_result {((e*d) % pi_n)};
    fmt::print("check: e*d mod pi_n = {}\n", check_result.get_str());

    // set private and public key
    private_key = std::make_pair(n, d);
    public_key  = std::make_pair(n, e);
}

auto RSA::get_key(const KeyType type) const noexcept-> std::string
{
    std::string output {};
    if (type == KeyType::PRIVATE)
    {
        output.append("[ " + private_key.first.get_str() 
                           + ", " 
                           + private_key.second.get_str()
                           + " ]"
                        ); 
    }
    else
    {
        output.append("[ " + public_key.first.get_str() 
                           + ", " 
                           + public_key.second.get_str()
                           + " ]"
                        ); 
    }

    return output;
}

auto RSA::is_valid() const noexcept -> bool
{
    return is_pq_valid;
}

auto RSA::crack_private_key(const Key& other_public_key) const noexcept -> Key
{
    // FIRST: get p and q 

    mpz_class kphi { d * e - 1 };
    mpz_class t {kphi};

    while (t % 2 == 0) {
        t /= 2;
    }
    
    mpz_class a {2};
    mpz_class q {0};
    bool found = false;

    while (!found) {
        mpz_class k {t};
        while (k < kphi) {
            mpz_class x {};
            // a^k mod n
            mpz_powm(x.get_mpz_t(), a.get_mpz_t(), k.get_mpz_t(), n.get_mpz_t());
            
            mpz_class x_sqrt_mod_n {};
            // x^2 mod n
            mpz_powm_ui(x_sqrt_mod_n.get_mpz_t(), x.get_mpz_t(), 2, n.get_mpz_t());

            if (x != t && x != (n - 1) && x_sqrt_mod_n == 1) {
                found = true;
                q = gcd(x - 1, n);
                break;
            }
            k *= 2;
        }
        a += 2;
    }

    mpz_class p { n / q };
    fmt::print("\nFound:\np: {}\nq: {}\n", p.get_str(), q.get_str());

    // Now, since we have p and q, as well as a victim's public key,
    // we can easly compute an inverse of that public key and we're gonna get a private key:

    Key cracked_key {this->n, {}};
    mpz_invert(cracked_key.second.get_mpz_t(), other_public_key.second.get_mpz_t(), this->pi_n.get_mpz_t());

    return cracked_key;
}

auto RSA::get_random_prime(std::mt19937& rng) noexcept -> mpz_class
{
    // 1. get random number from range <MIN_INT, MAX_INT) 
    // 2. get next prime number greater than number aquired from 1.

    std::uniform_int_distribution<uint64_t> distribution {MIN_INT, MAX_INT};

    uint64_t random_num {distribution(rng)};

    mpz_t p {random_num};  //TODO loosing precision here

    mpz_class out_number {};
    
    mpz_nextprime(out_number.get_mpz_t(), p);

    return out_number;
}   

auto RSA::is_prime(const mpz_class& n) noexcept -> bool
{
    if (mpz_probab_prime_p(n.get_mpz_t(), 30) == 0)
    {
        return false;
    }

    return true;
}