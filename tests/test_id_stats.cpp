#include <cmath>
#include <cstdlib>
#include <iostream>

#include "id_stats.h"

namespace {

bool nearlyEqual(double lhs, double rhs, double eps = 1e-12)
{
    return std::fabs(lhs - rhs) <= eps;
}

} // namespace

int main()
{
    const double balanced = fpsi::stats::compute_redundancy_rate(8, 8);
    if (!nearlyEqual(balanced, 0.0)) {
        std::cerr << "expected zero redundancy when filtered == used, got " << balanced << std::endl;
        return EXIT_FAILURE;
    }

    const double partial = fpsi::stats::compute_redundancy_rate(8, 4);
    if (!nearlyEqual(partial, 0.5)) {
        std::cerr << "expected redundancy 0.5 for filtered=8 used=4, got " << partial << std::endl;
        return EXIT_FAILURE;
    }

    const double inconsistent = fpsi::stats::compute_redundancy_rate(4, 8);
    if (!nearlyEqual(inconsistent, -1.0)) {
        std::cerr << "expected signed redundancy -1.0 for filtered=4 used=8, got " << inconsistent << std::endl;
        return EXIT_FAILURE;
    }

    const double empty = fpsi::stats::compute_redundancy_rate(0, 8);
    if (!nearlyEqual(empty, 0.0)) {
        std::cerr << "expected zero redundancy when filtered=0, got " << empty << std::endl;
        return EXIT_FAILURE;
    }

    const double invalidation = fpsi::stats::compute_filter_invalidation_rate(100, 95);
    if (!nearlyEqual(invalidation, 0.95)) {
        std::cerr << "expected filter invalidation rate 0.95 for generated=100 blocked=95, got " << invalidation << std::endl;
        return EXIT_FAILURE;
    }

    const double invalidationEmpty = fpsi::stats::compute_filter_invalidation_rate(0, 95);
    if (!nearlyEqual(invalidationEmpty, 0.0)) {
        std::cerr << "expected zero filter invalidation rate when generated=0, got " << invalidationEmpty << std::endl;
        return EXIT_FAILURE;
    }

    const double hitSetRedundancy = fpsi::stats::compute_hit_set_redundancy_rate(26, 8);
    if (!nearlyEqual(hitSetRedundancy, 18.0 / 26.0)) {
        std::cerr << "expected hit-set redundancy rate 18/26, got " << hitSetRedundancy << std::endl;
        return EXIT_FAILURE;
    }

    const double hitSetInconsistent = fpsi::stats::compute_hit_set_redundancy_rate(8, 26);
    if (!nearlyEqual(hitSetInconsistent, -18.0 / 8.0)) {
        std::cerr << "expected signed hit-set redundancy rate -(18/8), got " << hitSetInconsistent << std::endl;
        return EXIT_FAILURE;
    }

    const double hitSetEmpty = fpsi::stats::compute_hit_set_redundancy_rate(0, 8);
    if (!nearlyEqual(hitSetEmpty, 0.0)) {
        std::cerr << "expected zero hit-set redundancy rate when hits=0, got " << hitSetEmpty << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
