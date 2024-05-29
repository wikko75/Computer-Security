#include <fmt/ranges.h>
#include <bitset>
#include <string>
#include "RC4.hpp"


int main()
{
    uint8_t first_msg[] =  {"Hello, there!"};
    uint8_t second_msg[] = {"General Kenobi!"};

    std::string first_key_str {"key"};
    std::string second_key_str {"key2"};

    fmt::print("FIRST: KEY: {}\n", first_key_str);
    fmt::print("SECOND: KEY: {}\n\n", second_key_str);

    RC4 rc4_1 {first_key_str};
    RC4 rc4_2 {second_key_str};

    // encryption / decryption of first msg

    fmt::print("\nMessage: {} :  {}\n", (char*)(first_msg), first_msg);

    rc4_1.encrypt(first_msg, sizeof(first_msg));

    fmt::print("Encrypted: {} :  {}\n", (char*)(first_msg), first_msg);

    RC4::show_hex_rep(first_msg, sizeof(first_msg));

    rc4_1.decrypt(first_msg, sizeof(first_msg));

    fmt::print("Message: {} :  {}\n", (char*)(first_msg), first_msg);


    // encryption / decryption of second msg

    fmt::print("\nMessage: {} :  {}\n", (char*)(second_msg), second_msg);

    rc4_2.encrypt(second_msg, sizeof(second_msg));

    fmt::print("Encrypted: {} :  {}\n", (char*)(second_msg), second_msg);

    RC4::show_hex_rep(second_msg, sizeof(second_msg));

    rc4_2.decrypt(second_msg, sizeof(second_msg));

    fmt::print("Message: {} :  {}\n", (char*)(second_msg), second_msg);

    fmt::print("\n- {}\n- {}\n", (char*)first_msg, (char*)second_msg);


    // same key usage detection
    uint8_t sample_msg1[] = {"red flowers in water"};
    uint8_t sample_msg2[] = {"red flowers at water"};

    RC4 rc4_3 {"sampleKey1"};
    RC4 rc4_4 {"sampleKey2"};

    rc4_3.encrypt(sample_msg1, sizeof(sample_msg1));
    rc4_4.encrypt(sample_msg2, sizeof(sample_msg2));

    if(RC4::is_same_key_used_sm(sample_msg1, sample_msg2, sizeof(sample_msg1), sizeof(sample_msg2)))
    {
        fmt::print("Same key used!\n");
    }
    else
    {
        fmt::print("Not the same key used!\n");
    }

    if (RC4::is_same_key_used_dm(sample_msg1, sample_msg2, sizeof(sample_msg1), sizeof(sample_msg2)))
    {
        fmt::print("Same key used!\n");
    }
    else
    {
        fmt::print("Not the same key used!\n");
    }

    return 0;
}
