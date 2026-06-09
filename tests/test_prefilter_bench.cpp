#include <exception>
#include <iostream>
#include <string>

#include "cryptoTools/Common/CLP.h"
#include "prefilter_bench.h"

int main(int argc, char **argv)
{
    osuCrypto::CLP cmd;
    cmd.parse(argc, argv);

    fpsi::prefilter::PrefilterBenchConfig config;
    config.receiver_candidate_count = cmd.getOr<uint64_t>("n", 32768);
    config.ground_truth = cmd.getOr<uint64_t>("truth", 28);
    config.seed = cmd.getOr<uint64_t>("seed", 0);
    config.target_fpr = cmd.getOr<double>("fpr", 1e-3);
    config.try_count = cmd.getOr<uint64_t>("try", 1);
    config.filter = cmd.getOr<std::string>("filter", "all");

    try {
        const auto results = fpsi::prefilter::runPrefilterBenchmarks(config);
        fpsi::prefilter::printPrefilterBenchMarkdown(results, config);
        return 0;
    } catch (const std::exception &ex) {
        std::cerr << "test_prefilter_bench failed: " << ex.what() << std::endl;
        return 1;
    }
}
