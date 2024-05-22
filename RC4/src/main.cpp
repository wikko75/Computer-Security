#include <fmt/ranges.h>
#include <bitset>
#include <string>
#include "RC4.hpp"

void show_hex_rep(uint8_t msg[], uint64_t size);

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

    show_hex_rep(first_msg, sizeof(first_msg));

    rc4_1.decrypt(first_msg, sizeof(first_msg));

    fmt::print("Message: {} :  {}\n", (char*)(first_msg), first_msg);


    // encryption / decryption of second msg

    fmt::print("\nMessage: {} :  {}\n", (char*)(second_msg), second_msg);

    rc4_2.encrypt(second_msg, sizeof(second_msg));

    fmt::print("Encrypted: {} :  {}\n", (char*)(second_msg), second_msg);

    show_hex_rep(second_msg, sizeof(second_msg));

    rc4_2.decrypt(second_msg, sizeof(second_msg));

    fmt::print("Message: {} :  {}\n", (char*)(second_msg), second_msg);

    fmt::print("\n- {}\n- {}\n", (char*)first_msg, (char*)second_msg);


    // if(is_same_key_used(first_msg, second_msg, rc4_1, rc4_2))
    // {
    //     fmt::print("Same key used!\n");
    // }
    // else
    // {
    //     fmt::print("Not the same key used!\n");
        
    // }

    uint8_t msg[] = {"pedia"};

    RC4 rc4 {"Wiki"};

    fmt::print("\nMSG: {}\n", (char*)msg);

    fmt::print("SIZE: {}\n", sizeof(msg));

    rc4.encrypt(msg, sizeof(msg));

    show_hex_rep(msg, sizeof(msg));

    fmt::print("ENCODE: {}\n", (char*)msg);

    rc4.decrypt(msg, sizeof(msg));

    fmt::print("DECODE: {}\n", (char*)msg);

    return 0;

}

void show_hex_rep( uint8_t msg[], const uint64_t size)
{
    fmt::print("HEX: ");
    for (int i {0}; i < size - 1; ++i)
    {
        fmt::print("{:x} ", msg[i]);
    }

    fmt::print("\n");
}