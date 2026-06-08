#pragma once

#include <atomic>
#include <cstdint>
#include <iostream>
#include <string>

namespace fpsi::stats {

inline std::atomic<uint64_t> id_generated_total { 0 };
inline std::atomic<uint64_t> id_used_total { 0 };

inline void reset_id_stats()
{
    id_generated_total.store(0, std::memory_order_relaxed);
    id_used_total.store(0, std::memory_order_relaxed);
}

inline void print_id_stats(const std::string &label)
{
    const uint64_t generated = id_generated_total.load(std::memory_order_relaxed);
    const uint64_t used = id_used_total.load(std::memory_order_relaxed);
    const double redundancy = generated == 0 ? 0.0 : static_cast<double>(generated - used) / static_cast<double>(generated);

    std::cout << "[id-stats] " << label << std::endl;
    std::cout << "  id_generated_total = " << generated << std::endl;
    std::cout << "  id_used_total      = " << used << std::endl;
    std::cout << "  redundancy_rate    = (id_generated_total - id_used_total) / id_generated_total = " << redundancy << std::endl;
}

} // namespace fpsi::stats
