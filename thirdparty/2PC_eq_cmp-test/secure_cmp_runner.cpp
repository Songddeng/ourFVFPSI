#include <cstdint>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "secure_cmp_bridge.h"

namespace {

std::vector<uint64_t> readInput(const std::string &path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("failed to open cmp input: " + path);
    }

    uint64_t count = 0;
    in.read(reinterpret_cast<char *>(&count), sizeof(count));
    std::vector<uint64_t> values(count);
    if (count != 0) {
        in.read(reinterpret_cast<char *>(values.data()), static_cast<std::streamsize>(values.size() * sizeof(uint64_t)));
    }
    if (!in) {
        throw std::runtime_error("failed to read cmp input: " + path);
    }
    return values;
}

void writeOutput(const std::string &path, const std::vector<uint8_t> &shares)
{
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        throw std::runtime_error("failed to open cmp output: " + path);
    }

    const uint64_t count = shares.size();
    out.write(reinterpret_cast<const char *>(&count), sizeof(count));
    if (!shares.empty()) {
        out.write(reinterpret_cast<const char *>(shares.data()), static_cast<std::streamsize>(shares.size() * sizeof(uint8_t)));
    }
}

void writeProfile(const std::string &path, const secure_cmp_bridge::Profile &profile)
{
    std::ofstream out(path, std::ios::trunc);
    if (!out) {
        throw std::runtime_error("failed to open cmp profile: " + path);
    }

    out << profile.offline_ms << ' '
        << profile.online_ms << ' '
        << profile.offline_comm_bytes << ' '
        << profile.online_comm_bytes << '\n';
}

} // namespace

int main(int argc, char **argv)
{
    if (argc != 6 && argc != 7) {
        std::cerr << "usage: secure_cmp_runner <sender|receiver> <ip> <ell> <input.bin> <output.bin> [profile.txt]\n";
        return 2;
    }

    try {
        const std::string roleArg = argv[1];
        const std::string ip = argv[2];
        const uint32_t ell = static_cast<uint32_t>(std::stoul(argv[3]));
        const std::string inputPath = argv[4];
        const std::string outputPath = argv[5];
        const std::string profilePath = argc == 7 ? argv[6] : "";

        secure_cmp_bridge::Role role;
        if (roleArg == "sender") {
            role = secure_cmp_bridge::Role::Sender;
        } else if (roleArg == "receiver") {
            role = secure_cmp_bridge::Role::Receiver;
        } else {
            throw std::runtime_error("invalid role: " + roleArg);
        }

        std::vector<uint64_t> input = readInput(inputPath);
        std::vector<uint8_t> output;
        secure_cmp_bridge::Profile profile;
        secure_cmp_bridge::compare_u64(role, ip, input, ell, output, &profile);
        writeOutput(outputPath, output);
        if (!profilePath.empty()) {
            writeProfile(profilePath, profile);
        }
        return 0;
    } catch (const std::exception &e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
