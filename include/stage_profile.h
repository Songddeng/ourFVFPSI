#pragma once

#include <cmath>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <algorithm>
#include <iomanip>
#include <iostream>
#include <ostream>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include <cryptoTools/Common/Timer.h>

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

        os << std::setfill(' ');

        if (!title.empty()) {
            os << title << std::endl;
        }

        constexpr int kLabelWidth = 32;
        constexpr int kElapsedWidth = 11;
        constexpr int kDiffWidth = 12;
        constexpr int kCommWidth = 12;

        const int dividerWidth = kLabelWidth + kElapsedWidth + kDiffWidth + kCommWidth;
        os << std::left << std::setw(kLabelWidth) << "Label"
           << std::right << std::setw(kElapsedWidth) << "Time (ms)"
           << std::setw(kDiffWidth) << "diff (ms)"
           << std::setw(kCommWidth) << "Comm (MB)" << std::endl
           << std::string(dividerWidth, '_') << std::endl;

        double elapsed_ms = 0.0;
        for (const auto &entry : entries_) {
            if (entry.label == "prefilter done") {
                continue;
            }

            const double avg_diff_ms = entry.total_diff_ms / static_cast<double>(entry.count);
            const double avg_comm_mb = entry.total_comm_mb / static_cast<double>(entry.count);
            elapsed_ms += avg_diff_ms;

            os << std::left << std::setw(kLabelWidth) << normalizeStageLabel(entry.label)
               << std::right << std::setw(kElapsedWidth) << std::fixed << std::setprecision(1) << elapsed_ms
               << std::setw(kDiffWidth) << std::fixed << std::setprecision(3) << avg_diff_ms;

            if (std::fabs(avg_comm_mb) < 0.0005) {
                os << std::setw(kCommWidth) << "-";
            } else {
                os << std::setw(kCommWidth) << std::fixed << std::setprecision(3) << avg_comm_mb;
            }

            os << std::endl;
        }

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
    static std::string normalizeStageLabel(std::string_view label)
    {
        if (label == "fmap-prefix done") {
            return "fmap done";
        }
        return std::string(label);
    }

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

struct TimerProfileEntry {
    std::string label;
    double total_diff_ms = 0.0;
    uint64_t count = 0;
};

inline std::string normalizeTimerLabel(std::string_view label)
{
    if (label == "fmap-prefix done") {
        return "fmap done";
    }
    return std::string(label);
}

template <typename TimerLike>
inline std::vector<TimerProfileEntry> summarizeTimerProfile(const TimerLike &timer)
{
    std::vector<TimerProfileEntry> entries;
    std::unordered_map<std::string, size_t> index;

    if (timer.mTimes.empty()) {
        return entries;
    }

    auto previous = timer.mTimes.begin();
    auto iter = previous;
    ++iter;
    for (; iter != timer.mTimes.end(); ++iter) {
        if (iter->second == "begin") {
            previous = iter;
            continue;
        }

        const double diff_ms =
            std::chrono::duration_cast<std::chrono::microseconds>(iter->first - previous->first).count() / 1000.0;
        const std::string label = normalizeTimerLabel(iter->second);
        auto found = index.find(label);
        if (found == index.end()) {
            index[label] = entries.size();
            entries.push_back(TimerProfileEntry{ label, diff_ms, 1 });
        } else {
            auto &entry = entries[found->second];
            entry.total_diff_ms += diff_ms;
            entry.count += 1;
        }

        previous = iter;
    }

    return entries;
}

inline int stageStarCount(double diff_ms, double max_diff_ms)
{
    if (diff_ms < 1.0 || max_diff_ms <= 0.0) {
        return 0;
    }

    const double normalized = std::clamp(diff_ms / max_diff_ms, 0.0, 1.0);
    return std::clamp(static_cast<int>(std::lround(4.0 + normalized * 6.0)), 1, 10);
}

template <typename TimerLike>
inline void printTimerProfile(
    const TimerLike &timer,
    std::ostream &os = std::cout,
    const std::string &title = "")
{
    const auto oldFlags = os.flags();
    const auto oldPrecision = os.precision();
    const auto oldFill = os.fill();

    os << std::setfill(' ');

    if (!title.empty()) {
        os << title << std::endl;
    }

    const auto entries = summarizeTimerProfile(timer);
    constexpr int kLabelWidth = 32;
    constexpr int kElapsedWidth = 11;
    constexpr int kDiffWidth = 12;
    constexpr int kSpacerWidth = 3;
    const int dividerWidth = kLabelWidth + kElapsedWidth + kDiffWidth + kSpacerWidth + 10;

    os << std::left << std::setw(kLabelWidth) << "Label"
       << std::right << std::setw(kElapsedWidth) << "Time (ms)"
       << std::setw(kDiffWidth) << "diff (ms)" << std::endl
       << std::string(dividerWidth, '_') << std::endl;

    double elapsed_ms = 0.0;
    double max_diff_ms = 0.0;
    for (const auto &entry : entries) {
        max_diff_ms = std::max(max_diff_ms, entry.total_diff_ms / static_cast<double>(entry.count));
    }

    for (const auto &entry : entries) {
        const double avg_diff_ms = entry.total_diff_ms / static_cast<double>(entry.count);
        elapsed_ms += avg_diff_ms;
        const int stars = stageStarCount(avg_diff_ms, max_diff_ms);

        os << std::left << std::setw(kLabelWidth) << entry.label
           << std::right << std::setw(kElapsedWidth) << std::fixed << std::setprecision(1) << elapsed_ms
           << std::setw(kDiffWidth) << std::fixed << std::setprecision(3) << avg_diff_ms
           << std::string(kSpacerWidth, ' ');

        if (stars > 0) {
            os << std::string(static_cast<size_t>(stars), '*');
        }

        os << std::endl;
    }

    os.flags(oldFlags);
    os.precision(oldPrecision);
    os.fill(oldFill);
}

inline void printProtocolSummaryLine(
    std::ostream &os,
    const std::string &proto,
    const std::string &metric,
    size_t d,
    int delta,
    uint64_t n,
    double comm,
    double comp,
    double fmapComm,
    double filterComm,
    double otComm)
{
    const auto oldFlags = os.flags();
    const auto oldPrecision = os.precision();
    const auto oldFill = os.fill();

    os << std::setfill(' ')
       << std::left << std::setw(12) << proto
       << std::setw(8) << metric
       << std::right << std::setw(6) << d
       << std::setw(6) << delta
       << std::setw(8) << n
       << std::setw(11) << std::fixed << std::setprecision(3) << comm
       << std::setw(11) << comp
       << std::setw(11) << fmapComm
       << std::setw(11) << filterComm
       << std::setw(11) << otComm
       << std::endl;

    os.flags(oldFlags);
    os.precision(oldPrecision);
    os.fill(oldFill);
}
