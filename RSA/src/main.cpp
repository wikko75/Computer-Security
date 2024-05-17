#include <iostream>
#include <fmt/core.h>
#include <string>
#include <RSA.hpp>
#include <array>


auto show_keys(const RSA& rsa_object) -> void
{

    fmt::print("PRIVATE: [n, d] = {}\nPUBLIC:  [n, e] = {}\n",
                rsa_object.get_key(RSA::KeyType::PRIVATE),
                rsa_object.get_key(RSA::KeyType::PUBLIC)
                );
}


int main(int argc, char* args[])
{
    if (argc < 3)
    {
        fmt::print("p and q not provided!\n");
        return -1;
    }
    
    // sample prime numbers
    // 933710903884419601387274372609
    // 438579403791422990202215123491
    // {69761}; 
    // {56527};

    const mpz_class p (args[1]);
    const mpz_class q (args[2]);


    const RSA first_pair {p, q};
    const RSA second_pair {p, q};

    if (!first_pair.is_valid() || !second_pair.is_valid())
    {
        return -1;
    }

    fmt::print("\nFIRST_PAIR:\n");
    show_keys(first_pair);

    fmt::print("\nSECOND_PAIR:\n");
    show_keys(second_pair);

    auto cracked_key { first_pair.crack_private_key(second_pair.public_key) };
    fmt::print("\nCracked key: [n, d] = [ {}, {} ]\n", cracked_key.first.get_str(), cracked_key.second.get_str());

    return 0;
}

//! public: pk = (n, e); private: sk = (n, d)