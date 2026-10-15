// SPDX-License-Identifier: MIT
// Isolated mutation benchmark; no target execution or solver work.
#include <chrono>
#include <cstdint>
#include <ctime>
#include <iostream>
#include <vector>

#include "mutators/havoc.h"
#include "rng.h"
int main() {
    std::vector<std::uint8_t> bytes(32);
    for (std::size_t i = 0; i < bytes.size(); ++i) bytes[i] = static_cast<std::uint8_t>(i);
    mlfuzzz3::mutation::HavocMutator mutator;
    auto rng = mlfuzzz3::mutation::make_rng(1234);
    const mlfuzzz3::mutation::FuzzInput input(bytes);
    std::uint64_t checksum = 0;
    const auto cpu_start = std::clock();
    const auto start = std::chrono::steady_clock::now();
    for (unsigned i = 0; i < 300000; ++i) {
        const auto result = mutator.mutate(input, rng);
        checksum += result.size() + result.data()[0];
    }
    std::cout << std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count()
              << ' ' << static_cast<double>(std::clock() - cpu_start) / CLOCKS_PER_SEC << ' '
              << checksum << '\n';
}
