#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
    std::string input_str(reinterpret_cast<const char*>(Data), Size);
    std::cout << "Fuzzer string: " << input_str << std::endl;

    // Test if coverage guidance works
    if (input_str.size() >= 4 &&
        input_str[0] == 'f' &&
        input_str[1] == 'u' &&
        input_str[2] == 'z' &&
        input_str[3] == 'z') {

        std::cout << "That was the good input! Crashing now." << std::endl;
        std::abort();
    }

    // Test if ASAN works
    const std::string target_str = "asan_crash";
    if (input_str.size() >= target_str.size() &&
        input_str.substr(0, target_str.size()) == target_str) {

        std::cout << "Triggering asan! Crashing now." << std::endl;

        int* memory = new int[1];
        memory[1] = 123;  // out-of-bounds write, triggering asan
        delete[] memory;
    }

    return 0;
}