#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

#include "stage_profile.h"

struct FakeTimer {
    using timeUnit = std::chrono::system_clock::time_point;
    std::list<std::pair<timeUnit, std::string>> mTimes;
};

int main()
{
    StageProfileSummary summary;
    summary.add("offline preprocess OKVS done", 467.2, 0.0);
    summary.add("soOPRF Reverse done", 2061.5, 0.0);
    summary.add("prefilter done", 5.0, 9.9);
    summary.add("fmap done", 4589.8, 132.81);

    std::ostringstream oss;
    oss << std::setfill('0') << std::setw(8) << 42;
    summary.print(oss);

    const std::string output = oss.str();
    if (output.find("000000000") != std::string::npos) {
        std::cerr << "stage profile output leaked zero fill into the formatted table" << std::endl;
        return EXIT_FAILURE;
    }

    if (output.find("Label") == std::string::npos ||
        output.find("Time (ms)") == std::string::npos ||
        output.find("diff (ms)") == std::string::npos ||
        output.find("Comm (MB)") == std::string::npos) {
        std::cerr << "stage profile header did not match the expected aligned format" << std::endl;
        return EXIT_FAILURE;
    }

    if (output.find("offline preprocess OKVS done") == std::string::npos ||
        output.find("467.2") == std::string::npos ||
        output.find("           -") == std::string::npos) {
        std::cerr << "stage profile first row did not render as expected" << std::endl;
        return EXIT_FAILURE;
    }

    if (output.find("prefilter done") != std::string::npos) {
        std::cerr << "prefilter stage should not appear in the comm summary table" << std::endl;
        return EXIT_FAILURE;
    }

    if (output.find("fmap done") == std::string::npos ||
        output.find("7118.5") == std::string::npos ||
        output.find("4589.8") == std::string::npos ||
        output.find("132.810") == std::string::npos) {
        std::cerr << "stage profile comm column did not render as expected" << std::endl;
        return EXIT_FAILURE;
    }

    FakeTimer timer;
    const auto start = std::chrono::system_clock::time_point {};
    timer.mTimes.push_back({ start, "begin" });
    timer.mTimes.push_back({ start + std::chrono::microseconds(15336), "offline preprocess OKVS done" });
    timer.mTimes.push_back({ start + std::chrono::microseconds(112133), "soOPRF Reverse done" });
    timer.mTimes.push_back({ start + std::chrono::microseconds(187357), "siOPRF Reverse done" });
    timer.mTimes.push_back({ start + std::chrono::microseconds(267538), "soOPRF done" });
    timer.mTimes.push_back({ start + std::chrono::microseconds(335140), "siOPRF done" });
    timer.mTimes.push_back({ start + std::chrono::microseconds(335142), "fmap done" });
    timer.mTimes.push_back({ start + std::chrono::microseconds(489527), "filter done" });

    std::ostringstream timerOss;
    timerOss << std::setfill('0') << std::setw(4) << 7;
    printTimerProfile(timer, timerOss);
    const std::string timerOutput = timerOss.str();

    if (timerOutput.find("0000") != std::string::npos) {
        std::cerr << "timer profile output leaked zero fill into the formatted table" << std::endl;
        return EXIT_FAILURE;
    }

    if (timerOutput.find("Label") == std::string::npos ||
        timerOutput.find("diff (ms)") == std::string::npos ||
        timerOutput.find("offline preprocess OKVS done") == std::string::npos ||
        timerOutput.find("15.336") == std::string::npos ||
        timerOutput.find("*****") == std::string::npos ||
        timerOutput.find("fmap done") == std::string::npos ||
        timerOutput.find("0.002") == std::string::npos ||
        timerOutput.find("filter done") == std::string::npos ||
        timerOutput.find("**********") == std::string::npos) {
        std::cerr << "timer profile table did not render the expected star layout" << std::endl;
        return EXIT_FAILURE;
    }

    std::ostringstream summaryLine;
    printProtocolSummaryLine(summaryLine, "[ours]", "L1", 6, 5, 256, 8.522, 0.505, 5.486, 2.967, 0.069);
    const std::string lineOutput = summaryLine.str();
    if (lineOutput.find("[ours]") == std::string::npos ||
        lineOutput.find("L1") == std::string::npos ||
        lineOutput.find("256") == std::string::npos ||
        lineOutput.find("8.522") == std::string::npos ||
        lineOutput.find("0.505") == std::string::npos ||
        lineOutput.find("5.486") == std::string::npos ||
        lineOutput.find("2.967") == std::string::npos ||
        lineOutput.find("0.069") == std::string::npos) {
        std::cerr << "summary line did not render all expected fields" << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
