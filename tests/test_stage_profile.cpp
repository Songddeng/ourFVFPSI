#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

#include "stage_profile.h"

int main()
{
    StageProfileSummary summary;
    summary.add("offline preprocess OKVS done", 467.2, 0.0);
    summary.add("soOPRF Reverse done", 2061.5, 0.0);
    summary.add("fmap done", 4589.8, 132.81);

    std::ostringstream oss;
    oss << std::setfill('0') << std::setw(8) << 42;
    summary.print(oss, "[Timing]");

    const std::string output = oss.str();
    if (output.find("000000000") != std::string::npos) {
        std::cerr << "stage profile output leaked zero fill into the formatted table" << std::endl;
        return EXIT_FAILURE;
    }

    if (output.find("[Timing]") == std::string::npos ||
        output.find("Label") == std::string::npos ||
        output.find("Time (ms)") == std::string::npos ||
        output.find("Diff (ms)") == std::string::npos ||
        output.find("Comm (MB)") == std::string::npos) {
        std::cerr << "stage profile header did not match the expected aligned format" << std::endl;
        return EXIT_FAILURE;
    }

    if (output.find("offline preprocess OKVS done") == std::string::npos ||
        output.find("467.2") == std::string::npos ||
        output.find("|          -") == std::string::npos) {
        std::cerr << "stage profile first row did not render as expected" << std::endl;
        return EXIT_FAILURE;
    }

    if (output.find("fmap done") == std::string::npos ||
        output.find("7118.5") == std::string::npos ||
        output.find("4589.8") == std::string::npos ||
        output.find("132.81") == std::string::npos) {
        std::cerr << "stage profile comm column did not render as expected" << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
