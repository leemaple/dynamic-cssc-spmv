#pragma once

#include <cstdint>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace dynamic_cssc {

inline std::unordered_map<std::string, std::string> ParseArgs(int argc, char** argv) {
    std::unordered_map<std::string, std::string> result;
    for (int index = 1; index < argc; ++index) {
        std::string key = argv[index];
        if (key.rfind("--", 0) != 0) {
            throw std::invalid_argument("unexpected positional argument: " + key);
        }
        if (index + 1 >= argc) {
            throw std::invalid_argument("missing value for " + key);
        }
        const auto [iterator, inserted] = result.emplace(key.substr(2), argv[++index]);
        static_cast<void>(iterator);
        if (!inserted) {
            throw std::invalid_argument("duplicate argument: " + key);
        }
    }
    return result;
}

inline std::string GetString(
    const std::unordered_map<std::string, std::string>& args,
    const std::string& key,
    const std::string& fallback) {
    const auto iterator = args.find(key);
    return iterator == args.end() ? fallback : iterator->second;
}

inline std::uint32_t GetUInt(
    const std::unordered_map<std::string, std::string>& args,
    const std::string& key,
    std::uint32_t fallback) {
    const auto iterator = args.find(key);
    if (iterator == args.end()) {
        return fallback;
    }
    return static_cast<std::uint32_t>(std::stoul(iterator->second));
}

inline std::vector<int32_t> ParseIndices(const std::string& text) {
    std::vector<int32_t> indices;
    std::stringstream stream(text);
    std::string token;
    while (std::getline(stream, token, ',')) {
        if (!token.empty()) {
            indices.push_back(static_cast<int32_t>(std::stol(token)));
        }
    }
    return indices;
}

inline std::string JsonEscape(const std::string& value) {
    std::ostringstream output;
    for (const char character : value) {
        switch (character) {
            case '\\': output << "\\\\"; break;
            case '"': output << "\\\""; break;
            case '\n': output << "\\n"; break;
            case '\r': output << "\\r"; break;
            case '\t': output << "\\t"; break;
            default: output << character; break;
        }
    }
    return output.str();
}

}  // namespace dynamic_cssc
