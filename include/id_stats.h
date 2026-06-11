#pragma once

#include <atomic>
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

namespace fpsi::stats
{

    inline std::atomic<uint64_t> id_generated_total{0};
    inline std::atomic<uint64_t> id_filtered_total{0};
    inline std::atomic<uint64_t> id_used_total{0};

    inline void reset_id_stats()
    {
        id_generated_total.store(0, std::memory_order_relaxed);
        id_filtered_total.store(0, std::memory_order_relaxed);
        id_used_total.store(0, std::memory_order_relaxed);
    }

    inline double compute_redundancy_rate(uint64_t filtered, uint64_t used)
    {
        if (filtered == 0)
        {
            return 0.0;
        }

        const double filteredCount = static_cast<double>(filtered);
        const double usedCount = static_cast<double>(used);
        return (filteredCount - usedCount) / filteredCount;
    }

    struct FilterAuditStats
    {
        uint64_t s_id_generated_distinct = 0;
        uint64_t r_id_generated_distinct = 0;
        uint64_t true_intersection_estimate = 0;
        uint64_t r_total_hits = 0;
        uint64_t r_filtered_useless_ids = 0;
        uint64_t true_intersection_count = 0;
    };

    inline double compute_filter_invalidation_rate(uint64_t r_generated_distinct, uint64_t r_filtered_useless_ids)
    {
        if (r_generated_distinct == 0)
        {
            return 0.0;
        }

        return static_cast<double>(r_filtered_useless_ids) / static_cast<double>(r_generated_distinct);
    }

    inline double compute_hit_set_redundancy_rate(uint64_t r_total_hits, uint64_t true_intersection_count)
    {
        if (r_total_hits == 0)
        {
            return 0.0;
        }

        const double totalHits = static_cast<double>(r_total_hits);
        const double trueIntersectionCount = static_cast<double>(true_intersection_count);
        return (totalHits - trueIntersectionCount) / totalHits;
    }

    inline std::string format_summary_count(double value)
    {
        const double rounded = std::round(value);
        if (std::fabs(value - rounded) < 1e-9) {
            return std::to_string(static_cast<uint64_t>(rounded));
        }

        std::ostringstream oss;
        oss << std::fixed << std::setprecision(1) << value;
        return oss.str();
    }

    inline void print_filter_audit_stats(const std::string &label, const FilterAuditStats &stats, uint64_t num_runs = 1)
    {
        (void)label;
        const auto oldFlags = std::cout.flags();
        const auto oldPrecision = std::cout.precision();
        const auto oldFill = std::cout.fill();

        const double runs = static_cast<double>(std::max<uint64_t>(num_runs, 1));
        const double avgTrueIntersectionEstimate = static_cast<double>(stats.true_intersection_estimate) / runs;
        const double avgTotalHits = static_cast<double>(stats.r_total_hits) / runs;

        std::cout << std::setfill(' ');
        std::cout << "[Summary] True_Intersection_Estimate = "
                  << format_summary_count(avgTrueIntersectionEstimate)
                  << " | Total Hits = " << format_summary_count(avgTotalHits)
                  << std::endl;
        // std::cout << std::fixed << std::setprecision(3);
        // std::cout << "  Filter_Efficiency_Rate: (R_Blocked_Useless / R_Generated) = "
        //           << invalidationRate << " (" << (invalidationRate * 100.0) << "%)" << std::endl;
        // std::cout << "  Truth_Intersection_Result: id_used_total = "
        //           << stats.true_intersection_count << std::endl;
        // std::cout << "  Hit_Set_Redundancy_Rate: (R_Total_Hits - id_used_total) / R_Total_Hits = "
        //           << hitSetRedundancyRate << " (" << (hitSetRedundancyRate * 100.0) << "%)" << std::endl;

        std::cout.flags(oldFlags);
        std::cout.precision(oldPrecision);
        std::cout.fill(oldFill);
    }

    inline void print_id_stats(const std::string &label)
    {
        const uint64_t generated = id_generated_total.load(std::memory_order_relaxed);
        const uint64_t filtered = id_filtered_total.load(std::memory_order_relaxed);
        const uint64_t used = id_used_total.load(std::memory_order_relaxed);
        const double redundancy = compute_redundancy_rate(filtered, used);

        std::cout << "[id-stats] " << label << std::endl;
        // std::cout << "  原本---过滤后: " << generated << " ---> " << filtered << std::endl;
        std::cout << "  id_generated_total = " << generated << std::endl;
        // std::cout << "  id_filtered_total  = " << filtered << std::endl;
        std::cout << "  id_used_total      = " << used << std::endl;
        std::cout << "  redundancy_rate    = (" << filtered << " - " << used << ") / " << filtered << " = " << redundancy << std::endl;
    }

} // namespace fpsi::stats
