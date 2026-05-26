#pragma once

#include <chrono>
#include <cstdint>
#include <iostream>
#include <map>
#include <string>
#include <sys/types.h>

struct TimerStat {
    uint64_t accumulated_time;
    uint64_t accumulated_comm;
    uint64_t start_time;
    uint64_t start_comm;
};

extern std::map<std::string, TimerStat> timers;

inline void start_timer(const std::string &name)
{
    timers[name].start_time = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();

    // timers[name].start_comm = ios[0]->counter + ios[1]->counter;
}

inline void stop_timer(const std::string &name)
{
    uint64_t end = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    timers[name].accumulated_time += end - timers[name].start_time;

    // timers[name].accumulated_comm += (ios[0]->counter + ios[1]->counter) - timers[name].start_comm;
}

inline void print_timer(const std::string &name)
{
    std::cout << name << ": " << timers[name].accumulated_time << " ms, " << (timers[name].accumulated_comm / 1024.0 / 1024.0) << " MB" << std::endl;
}

inline void print_all_timers(const std::string &prefix)
{
    for (auto &timer : timers) {
        if (prefix.empty() || timer.first.find(prefix) == 0) {
            print_timer(timer.first);
        }
    }
}
