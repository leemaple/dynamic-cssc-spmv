#include "openfhe.h"
#include "ciphertext-ser.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <functional>
#include <iostream>
#include <numeric>
#include <sstream>
#include <string>
#include <vector>

#include "include/args.hpp"

using namespace lbcrypto;

namespace {

using Clock = std::chrono::steady_clock;

struct Summary {
    double medianMs;
    double p95Ms;
    std::size_t repetitions;
};

Summary Summarize(std::vector<double> values) {
    if (values.empty()) {
        return {0.0, 0.0, 0};
    }
    std::sort(values.begin(), values.end());
    const auto medianIndex = values.size() / 2;
    const auto p95Index = static_cast<std::size_t>(
        std::ceil(0.95 * static_cast<double>(values.size()))) - 1;
    return {values[medianIndex], values[std::min(p95Index, values.size() - 1)], values.size()};
}

template <class Function>
Summary Measure(Function&& function, std::size_t warmups, std::size_t repetitions) {
    for (std::size_t index = 0; index < warmups; ++index) {
        function();
    }
    std::vector<double> values;
    values.reserve(repetitions);
    for (std::size_t index = 0; index < repetitions; ++index) {
        const auto begin = Clock::now();
        function();
        const auto end = Clock::now();
        values.push_back(std::chrono::duration<double, std::milli>(end - begin).count());
    }
    return Summarize(std::move(values));
}

CryptoContext<DCRTPoly> MakeContext(
    std::uint32_t ringDim,
    std::uint64_t plaintextModulus,
    std::uint32_t batchSize,
    std::uint32_t multiplicativeDepth) {
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(plaintextModulus);
    parameters.SetMultiplicativeDepth(multiplicativeDepth);
    parameters.SetSecurityLevel(HEStd_128_classic);
    parameters.SetRingDim(ringDim);
    parameters.SetBatchSize(batchSize);
    parameters.SetKeySwitchTechnique(HYBRID);
    parameters.SetMultiplicationTechnique(HPSPOVERQLEVELED);
    auto context = GenCryptoContext(parameters);
    context->Enable(PKE);
    context->Enable(KEYSWITCH);
    context->Enable(LEVELEDSHE);
    context->Enable(ADVANCEDSHE);
    return context;
}

void WriteSummary(std::ostream& output, const std::string& name, const Summary& summary, bool comma) {
    output << "    \"" << name << "\": {\"median_ms\": " << summary.medianMs
           << ", \"p95_ms\": " << summary.p95Ms
           << ", \"repetitions\": " << summary.repetitions << '}';
    if (comma) {
        output << ',';
    }
    output << '\n';
}

}  // namespace

int main(int argc, char** argv) {
    try {
        const auto args = dynamic_cssc::ParseArgs(argc, argv);
        const auto outputPath = dynamic_cssc::GetString(args, "output", "microbench.json");
        const auto ringDim = dynamic_cssc::GetUInt(args, "ring-dim", 8192);
        const auto plaintextModulus = dynamic_cssc::GetUInt(args, "plaintext-modulus", 65537);
        const auto batchSize = dynamic_cssc::GetUInt(args, "batch-size", ringDim);
        const auto multiplicativeDepth = dynamic_cssc::GetUInt(args, "multiplicative-depth", 2);
        const auto noiseBudgetProfile = dynamic_cssc::GetString(
            args, "noise-budget-profile", "");
        const auto warmups = dynamic_cssc::GetUInt(args, "warmups", 3);
        const auto repetitions = dynamic_cssc::GetUInt(args, "repetitions", 11);
        const auto rotationIndices = dynamic_cssc::ParseIndices(
            dynamic_cssc::GetString(args, "indices", "1,-1,2,-2,4,-4,8,-8"));
        const int32_t measuredRotation = rotationIndices.empty() ? 1 : rotationIndices.front();

        if (noiseBudgetProfile != "day2_mult_only") {
            std::cerr << "noise-budget-profile must be day2_mult_only\n";
            return 5;
        }

        auto context = MakeContext(ringDim, plaintextModulus, batchSize, multiplicativeDepth);
        const auto keyPair = context->KeyGen();
        context->EvalMultKeyGen(keyPair.secretKey);
        context->EvalRotateKeyGen(keyPair.secretKey, rotationIndices);

        std::vector<int64_t> values(batchSize, 1);
        std::vector<int64_t> maskValues(batchSize, 0);
        for (std::size_t index = 0; index < maskValues.size(); index += 2) {
            maskValues[index] = 1;
        }

        Plaintext plaintext;
        Plaintext maskPlaintext;
        Ciphertext<DCRTPoly> ciphertext;
        Ciphertext<DCRTPoly> ciphertext2;
        Ciphertext<DCRTPoly> sink;
        Plaintext decrypted;
        std::string serialized;

        const auto encode = Measure(
            [&] { plaintext = context->MakePackedPlaintext(values); }, warmups, repetitions);
        plaintext = context->MakePackedPlaintext(values);
        maskPlaintext = context->MakePackedPlaintext(maskValues);
        const auto encrypt = Measure(
            [&] { ciphertext = context->Encrypt(keyPair.publicKey, plaintext); }, warmups, repetitions);
        ciphertext = context->Encrypt(keyPair.publicKey, plaintext);
        ciphertext2 = context->Encrypt(keyPair.publicKey, plaintext);

        const auto serialize = Measure(
            [&] {
                std::stringstream stream;
                Serial::Serialize(ciphertext, stream, SerType::BINARY);
                serialized = stream.str();
            },
            warmups,
            repetitions);
        {
            std::stringstream stream;
            Serial::Serialize(ciphertext, stream, SerType::BINARY);
            serialized = stream.str();
        }
        const auto deserialize = Measure(
            [&] {
                std::stringstream stream(serialized);
                Ciphertext<DCRTPoly> restored;
                Serial::Deserialize(restored, stream, SerType::BINARY);
                sink = restored;
            },
            warmups,
            repetitions);
        const auto evalMult = Measure(
            [&] { sink = context->EvalMult(ciphertext, ciphertext2); }, warmups, repetitions);
        const auto evalRotate = Measure(
            [&] { sink = context->EvalRotate(ciphertext, measuredRotation); }, warmups, repetitions);
        const auto evalAddCiphertext = Measure(
            [&] { sink = context->EvalAdd(ciphertext, ciphertext2); }, warmups, repetitions);
        const auto evalAddPlaintext = Measure(
            [&] { sink = context->EvalAdd(ciphertext, maskPlaintext); }, warmups, repetitions);
        const auto evalMask = Measure(
            [&] { sink = context->EvalMult(ciphertext, maskPlaintext); }, warmups, repetitions);
        const auto decrypt = Measure(
            [&] { context->Decrypt(keyPair.secretKey, ciphertext, &decrypted); }, warmups, repetitions);

        std::stringstream keyStream;
        if (!context->SerializeEvalAutomorphismKey(keyStream, SerType::BINARY)) {
            std::cerr << "warning: rotation-key serialization returned false\n";
        }
        const auto rotationKeyBytes = keyStream.str().size();

        std::ofstream output(outputPath, std::ios::out | std::ios::trunc);
        if (!output) {
            std::cerr << "cannot open output: " << outputPath << '\n';
            return 4;
        }
        output << "{\n";
        output << "  \"status\": \"measured-openfhe\",\n";
        output << "  \"noise_budget_profile\": \""
               << dynamic_cssc::JsonEscape(noiseBudgetProfile) << "\",\n";
        output << "  \"evidence_scope\": \"isolated-unit-probe-only\",\n";
        output << "  \"mixed_workload_formal_parameter_claim_allowed\": false,\n";
        output << "  \"eval_mult_includes_relinearization\": true,\n";
        output << "  \"measured_rotation_index\": " << measuredRotation << ",\n";
        output << "  \"ciphertext_bytes\": " << serialized.size() << ",\n";
        output << "  \"rotation_key_bytes\": " << rotationKeyBytes << ",\n";
        output << "  \"operations\": {\n";
        WriteSummary(output, "encode", encode, true);
        WriteSummary(output, "encrypt", encrypt, true);
        WriteSummary(output, "serialize_ciphertext", serialize, true);
        WriteSummary(output, "deserialize_ciphertext", deserialize, true);
        WriteSummary(output, "eval_mult_with_relinearization", evalMult, true);
        WriteSummary(output, "eval_rotate", evalRotate, true);
        WriteSummary(output, "eval_add_ciphertext", evalAddCiphertext, true);
        WriteSummary(output, "eval_add_plaintext_blinding", evalAddPlaintext, true);
        WriteSummary(output, "eval_mult_plaintext_mask", evalMask, true);
        WriteSummary(output, "decrypt", decrypt, false);
        output << "  }\n";
        output << "}\n";
        std::cout << outputPath << '\n';
        return 0;
    }
    catch (const std::exception& exception) {
        std::cerr << "openfhe_microbench failed: " << exception.what() << '\n';
        return 1;
    }
}
