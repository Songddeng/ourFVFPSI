#pragma once

#include <cmath>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <ostream>
#include <string>
#include <unordered_map>
#include <vector>

struct StageProfileEntry {
    std::string label;
    double total_diff_ms = 0.0;
    double total_comm_mb = 0.0;
    uint64_t count = 0;
};

class StageProfileSummary {
public:
    void add(const std::string &label, double diff_ms, double comm_mb)
    {
        auto iter = index_.find(label);
        if (iter == index_.end()) {
            index_[label] = entries_.size();
            entries_.push_back(StageProfileEntry{ label, diff_ms, comm_mb, 1 });
            return;
        }

        auto &entry = entries_[iter->second];
        entry.total_diff_ms += diff_ms;
        entry.total_comm_mb += comm_mb;
        entry.count += 1;
    }

    void print(std::ostream &os = std::cout, const std::string &title = "") const
    {
        const auto oldFlags = os.flags();
        const auto oldPrecision = os.precision();
        const auto oldFill = os.fill();

        constexpr int kLabelWidth = 30;
        constexpr int kMetricWidth = 10;
        constexpr const char *kDivider = "----------------------------------------------------------------------";

        os << std::setfill(' ');

        if (!title.empty()) {
            os << title << std::endl;
        }

        os << kDivider << std::endl;
        os << std::left << std::setw(kLabelWidth) << "Label"
           << " | " << std::right << std::setw(kMetricWidth) << "Time (ms)"
           << " | " << std::setw(kMetricWidth) << "Diff (ms)"
           << " | " << std::setw(kMetricWidth) << "Comm (MB)" << std::endl;
        os << kDivider << std::endl;

        double elapsed_ms = 0.0;
        for (const auto &entry : entries_) {
            const double avg_diff_ms = entry.total_diff_ms / static_cast<double>(entry.count);
            const double avg_comm_mb = entry.total_comm_mb / static_cast<double>(entry.count);
            elapsed_ms += avg_diff_ms;

            os << std::left << std::setw(kLabelWidth) << entry.label
               << " | " << std::right << std::setw(kMetricWidth) << std::fixed << std::setprecision(1) << elapsed_ms
               << " | " << std::setw(kMetricWidth) << std::fixed << std::setprecision(1) << avg_diff_ms
               << " | ";

            if (std::fabs(avg_comm_mb) < 0.005) {
                os << std::setw(kMetricWidth) << "-";
            } else {
                os << std::setw(kMetricWidth) << std::fixed << std::setprecision(2) << avg_comm_mb;
            }

            os << std::endl;
        }

        os << kDivider << std::endl;

        os.flags(oldFlags);
        os.precision(oldPrecision);
        os.fill(oldFill);
    }

    double getAverageCommMB(const std::string &label) const
    {
        auto iter = index_.find(label);
        if (iter == index_.end()) {
            return 0.0;
        }

        const auto &entry = entries_[iter->second];
        return entry.total_comm_mb / static_cast<double>(entry.count);
    }

private:
    std::vector<StageProfileEntry> entries_;
    std::unordered_map<std::string, size_t> index_;
};

class StageProfileRun {
public:
    using Clock = std::chrono::steady_clock;

    explicit StageProfileRun(StageProfileSummary &summary)
        : summary_(summary)
    {
    }

    void start(uint64_t base_comm_bytes)
    {
        last_time_ = Clock::now();
        last_comm_bytes_ = base_comm_bytes;
        started_ = true;
    }

    void mark(const std::string &label, uint64_t current_comm_bytes)
    {
        if (!started_) {
            start(current_comm_bytes);
        }

        const auto now = Clock::now();
        const double diff_ms = std::chrono::duration_cast<std::chrono::microseconds>(now - last_time_).count() / 1000.0;
        const double comm_mb = static_cast<double>(current_comm_bytes - last_comm_bytes_) / 1024.0 / 1024.0;

        summary_.add(label, diff_ms, comm_mb);

        last_time_ = now;
        last_comm_bytes_ = current_comm_bytes;
    }

private:
    StageProfileSummary &summary_;
    Clock::time_point last_time_;
    uint64_t last_comm_bytes_ = 0;
    bool started_ = false;
};
