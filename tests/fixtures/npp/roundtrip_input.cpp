// roundtrip_input.cpp — fixture for Weave E3-M2 file-open probe gate
// This file is opened by NPP during the notepad_roundtrip_file_open_probe test.
// It must be valid C++ and small enough to load quickly.

#include <iostream>
#include <string>
#include <vector>

namespace weave_test {

struct Greeting {
    std::string message;
    int repeat;
};

void print_greeting(const Greeting& g) {
    for (int i = 0; i < g.repeat; ++i) {
        std::cout << g.message << "\n";
    }
}

} // namespace weave_test

int main() {
    weave_test::Greeting g{"Hello, Weave!", 3};
    weave_test::print_greeting(g);
    return 0;
}
