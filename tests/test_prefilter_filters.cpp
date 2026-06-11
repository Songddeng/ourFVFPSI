#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <unordered_set>

#include "prefilter_bench.h"

namespace {

using fpsi::prefilter::PrefilterKind;

std::string kindLabel(PrefilterKind kind)
{
    return fpsi::prefilter::prefilterKindName(kind);
}

void require(bool condition, const std::string &message)
{
    if (!condition) {
        throw std::runtime_error(message);
    }
}

} // namespace

int main()
{
    try {
        const auto allKinds = fpsi::prefilter::parsePrefilterSelection("all");
        require(allKinds.size() == 5, "expected all selection to include five filters");

        const auto vbfKinds = fpsi::prefilter::parsePrefilterSelection("vbf");
        require(vbfKinds.size() == 1 && vbfKinds.front() == PrefilterKind::VirtualBloom, "expected vbf selection to resolve to Virtual Bloom Filter");
        const auto bfuseKinds = fpsi::prefilter::parsePrefilterSelection("bfuse");
        require(bfuseKinds.size() == 1 && bfuseKinds.front() == PrefilterKind::BinaryFuse, "expected bfuse selection to resolve to Binary Fuse Filter");

        const auto dataset = fpsi::prefilter::generatePrefilterDataset(4096, 128, 7);
        require(!dataset.sender_ids.empty(), "sender dataset must not be empty");
        require(dataset.receiver_ids.size() == 4096, "receiver dataset size mismatch");

        for (PrefilterKind kind : allKinds) {
            const auto serialized = fpsi::prefilter::buildSerializedPrefilter(kind, dataset.sender_ids, 1e-3);
            require(!serialized.empty(), "serialized filter is unexpectedly empty for " + kindLabel(kind));

            const auto hits = fpsi::prefilter::querySerializedPrefilter(kind, serialized, dataset.receiver_ids);
            require(!hits.empty(), "query returned no hits for " + kindLabel(kind));

            std::unordered_set<uint32_t> hitSet(hits.begin(), hits.end());
            uint64_t truePositives = 0;
            for (uint32_t index = 0; index < dataset.receiver_ids.size(); ++index) {
                if (dataset.receiver_truth_mask[index] == 1) {
                    if (hitSet.contains(index)) {
                        ++truePositives;
                    } else {
                        throw std::runtime_error("false negative detected for " + kindLabel(kind));
                    }
                }
            }

            require(
                truePositives == 128,
                "true positive count mismatch for " + kindLabel(kind));
        }

        return EXIT_SUCCESS;
    } catch (const std::exception &ex) {
        std::cerr << "test_prefilter_filters failed: " << ex.what() << std::endl;
        return EXIT_FAILURE;
    }
}
