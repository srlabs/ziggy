#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <string>

//// Fuzzer initialization. This function is obligatory, otherwise you'll have linker issues with Ziggy!
/// If you don't want any initialization, just `return 0;`
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    std::cout << "Hello from LLVMFuzzerInitialize!" << std::endl;
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
    std::string input_str(reinterpret_cast<const char*>(Data), Size);
    std::cout << "Fuzzer string: " << input_str << std::endl;

    // Test if coverage guidance works
    if (input_str.size() >= 4 &&
        input_str[0] == 'f' &&
        input_str[1] == 'u' &&
        input_str[2] == 'z' &&
        input_str[3] == 'z') {

       int* memory = new int[1];
       memory[1] = 123;  // out-of-bounds write, triggering asan
       delete[] memory;
    }

    //Test if ASAN works AND CMPLOG/RedQueen
    //However if compiled with `--lto` it won't necessarily mean that the string was guessed with CMPLOG since AFL LTO mode has a auto-dictionnary feature
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


/// This `main()` function is used to create coverage.
#ifdef ENABLE_FUZZ_MAIN
int main(int argc, char **argv) {
  if (LLVMFuzzerInitialize) {
    fprintf(stderr, "Running LLVMFuzzerInitialize ...\n");
    LLVMFuzzerInitialize(&argc, &argv);
  }

  for (int i = 1; i < argc; i++) {
    FILE *f = fopen(argv[i], "r");
    if (f) {
      fseek(f, 0, SEEK_END);
      size_t len = ftell(f);
      fseek(f, 0, SEEK_SET);
      unsigned char *buf = (unsigned char *)malloc(len);

      if (buf) {
        size_t n_read = fread(buf, 1, len, f);
        fclose(f);

        if (n_read > 0) {
          fprintf(stderr, "Running: %s (%d/%d) %zu bytes\n", argv[i], i,
                  argc - 1, n_read);
          LLVMFuzzerTestOneInput((const unsigned char *)buf, len);
        }

        free(buf);
      }
    }
  }

  fprintf(stderr, "Done.\n");
  return 0;
}
#endif