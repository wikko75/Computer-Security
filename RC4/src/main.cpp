#include <fmt/ranges.h>
#include <bitset>
#include <string>
#include "RC4.hpp"


void show_hex_rep(uint8_t msg[], uint64_t size);


// assumption -> both messages are similar
bool is_same_key_used(uint8_t msg1[], uint8_t msg2[], uint64_t size1, uint64_t size2);


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



    uint8_t msg[] = {"pedia"};

    RC4 rc4 {"Wiki"};

    fmt::print("\nMSG: {}\n", (char*)msg);

    fmt::print("SIZE: {}\n", sizeof(msg));

    rc4.encrypt(msg, sizeof(msg));

    show_hex_rep(msg, sizeof(msg));

    fmt::print("ENCODE: {}\n", (char*)msg);

    rc4.decrypt(msg, sizeof(msg));

    fmt::print("DECODE: {}\n", (char*)msg);


    uint8_t sample_msg1[] = {"red flowers in water"};
    uint8_t sample_msg2[] = {"red flowers at water"};

    RC4 rc4_3 {"sampleKey1"};
    RC4 rc4_4 {"sampleKey1"};

    rc4_3.encrypt(sample_msg1, sizeof(sample_msg1));
    rc4_4.encrypt(sample_msg2, sizeof(sample_msg2));

    if(is_same_key_used(sample_msg1, sample_msg2, sizeof(sample_msg1), sizeof(sample_msg2)))
    {
        fmt::print("Same key used!\n");
    }
    else
    {
        fmt::print("Not the same key used!\n");
    }

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

bool is_same_key_used(uint8_t msg1[], uint8_t msg2[], uint64_t size1, uint64_t size2)
{
    uint64_t min_size {size1 < size2 ? size1 : size2};
    uint8_t* xor_result { new uint8_t[min_size]};

    // perform XOR on msg1 and msg2 bytes
    for (size_t i {0}; i < min_size - 1; ++i)
    {
        xor_result[i] = msg1[i] ^ msg2[i];
    }

    fmt::print("First Cipher ");
    show_hex_rep(msg1, size1);
    
    fmt::print("Second Cipher ");
    show_hex_rep(msg2, size2);

    fmt::print("XOR ");
    show_hex_rep(xor_result, min_size);

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