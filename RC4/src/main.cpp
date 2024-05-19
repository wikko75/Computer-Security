#include <fmt/ranges.h>
#include <bitset>
#include <string>
#include "RC4.hpp"


int main()
{
    uint8_t first_msg[] =  {"Hello, there!"};
    uint8_t second_msg[] = {"General Kenobi!"};

    std::bitset<128> first_key  {0b01001000010101100010001010000101111101011010101};
    std::bitset<128> second_key {0b01100000010101101010001010010010011010101111010};

    std::string first_key_str {first_key.to_string()};
    std::string second_key_str {second_key.to_string()};

    fmt::print("FIRST: KEY: {}\n", first_key_str);
    fmt::print("SECOND: KEY: {}\n\n", second_key_str);

    RC4 rc4_1 {first_key_str};
    RC4 rc4_2 {second_key_str};

    // encryption / decryption of first msg

    fmt::print("\nMessage: {} :  {}\n", (char*)(first_msg), first_msg);

    rc4_1.encrypt(first_msg, sizeof(first_msg));

    fmt::print("Encrypted: {} :  {}\n", (char*)(first_msg), first_msg);

    rc4_1.decrypt(first_msg, sizeof(first_msg));

    fmt::print("Message: {} :  {}\n", (char*)(first_msg), first_msg);


    // encryption / decryption of second msg

    fmt::print("\nMessage: {} :  {}\n", (char*)(second_msg), second_msg);

    rc4_2.encrypt(second_msg, sizeof(second_msg));

    fmt::print("Encrypted: {} :  {}\n", (char*)(second_msg), second_msg);

    rc4_2.decrypt(second_msg, sizeof(second_msg));

    fmt::print("Message: {} :  {}\n", (char*)(second_msg), second_msg);

    fmt::print("\n- {}\n- {}", (char*)first_msg, (char*)second_msg);
    
    return 0;
}