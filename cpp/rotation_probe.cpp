#include "openfhe.h"

#include <cstdint>
#include <fstream>
#include <iostream>
#include <memory>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "include/args.hpp"

using namespace lbcrypto;

namespace {

CryptoContext<DCRTPoly> MakeContext(
    std::uint32_t ringDim,
    std::uint64_t plaintextModulus,
    std::uint32_t batchSize,
    std::uint32_t multiplicativeDepth,
    std::uint32_t evalAddCount,
    std::uint32_t keySwitchCount) {
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(plaintextModulus);
    parameters.SetMultiplicativeDepth(multiplicativeDepth);
    parameters.SetSecurityLevel(HEStd_128_classic);
    parameters.SetRingDim(ringDim);
    parameters.SetBatchSize(batchSize);
    parameters.SetEvalAddCount(evalAddCount);
    parameters.SetKeySwitchCount(keySwitchCount);
    parameters.SetKeySwitchTechnique(HYBRID);
    parameters.SetMultiplicationTechnique(HPSPOVERQLEVELED);

    auto context = GenCryptoContext(parameters);
    context->Enable(PKE);
    context->Enable(KEYSWITCH);
    context->Enable(LEVELEDSHE);
    context->Enable(ADVANCEDSHE);
    return context;
}

void WriteVector(std::ostream& output, const std::vector<int64_t>& values) {
    output << '[';
    for (std::size_t index = 0; index < values.size(); ++index) {
        if (index != 0) {
            output << ',';
        }
        output << values[index];
    }
    output << ']';
}

bool IsFrozenLabelPermutation(
    const std::vector<int64_t>& values,
    std::uint32_t batchSize) {
    if (values.size() != batchSize) {
        return false;
    }
    std::vector<bool> seen(batchSize, false);
    for (const auto value : values) {
        if (value < 0 || value >= static_cast<int64_t>(batchSize)) {
            return false;
        }
        const auto index = static_cast<std::size_t>(value);
        if (seen[index]) {
            return false;
        }
        seen[index] = true;
    }
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        const auto args = dynamic_cssc::ParseArgs(argc, argv);
        const auto outputPath = dynamic_cssc::GetString(args, "output", "rotation_layout.json");
        const auto ringDim = dynamic_cssc::GetUInt(args, "ring-dim", 8192);
        const auto plaintextModulus = dynamic_cssc::GetUInt(args, "plaintext-modulus", 65537);
        const auto batchSize = dynamic_cssc::GetUInt(args, "batch-size", ringDim);
        const auto multiplicativeDepth = dynamic_cssc::GetUInt(args, "multiplicative-depth", 2);
        const auto evalAddCount = dynamic_cssc::GetUInt(args, "eval-add-count", 128);
        const auto keySwitchCount = dynamic_cssc::GetUInt(args, "key-switch-count", 16);
        const auto requested = dynamic_cssc::ParseIndices(dynamic_cssc::GetString(
            args,
            "indices",
            "1,-1,2,-2,4,-4,8,-8,16,-16,32,-32,64,-64,128,-128,256,-256,512,-512,1024,-1024,2048,-2048,4095,-4095,4096"));

        if (plaintextModulus <= batchSize) {
            std::cerr << "plaintext modulus must exceed batch size so P0a labels remain unique\n";
            return 2;
        }
        if (requested.empty()) {
            std::cerr << "at least one rotation index is required\n";
            return 6;
        }

        auto context = MakeContext(
            ringDim,
            plaintextModulus,
            batchSize,
            multiplicativeDepth,
            evalAddCount,
            keySwitchCount);
        const auto cryptoParameters = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(
            context->GetCryptoParameters());
        if (!cryptoParameters) {
            std::cerr << "generated context does not expose BFVRNS parameters\n";
            return 7;
        }
        const auto contextEvalAddCount = cryptoParameters->GetEvalAddCount();
        const auto contextKeySwitchCount = cryptoParameters->GetKeySwitchCount();
        if (contextEvalAddCount != evalAddCount || contextKeySwitchCount != keySwitchCount) {
            std::cerr << "generated context does not preserve the frozen noise-budget counts\n";
            return 7;
        }
        const auto keyPair = context->KeyGen();
        if (!keyPair.good()) {
            std::cerr << "key generation failed\n";
            return 3;
        }

        std::vector<int64_t> labels(batchSize);
        for (std::uint32_t index = 0; index < batchSize; ++index) {
            labels[index] = static_cast<int64_t>(index);
        }
        const auto plaintext = context->MakePackedPlaintext(labels);
        const auto ciphertext = context->Encrypt(keyPair.publicKey, plaintext);

        struct ProbeResult {
            int32_t index;
            bool keyGenerated;
            bool evaluationSucceeded;
            bool decryptValid;
            bool isPermutation;
            std::string error;
            std::vector<int64_t> permutation;
        };
        std::vector<ProbeResult> results;
        results.reserve(requested.size());
        bool allProbesValid = true;

        for (const auto rotationIndex : requested) {
            ProbeResult result{rotationIndex, false, false, false, false, "", {}};
            try {
                context->EvalRotateKeyGen(keyPair.secretKey, {rotationIndex});
                result.keyGenerated = true;
                const auto rotated = context->EvalRotate(ciphertext, rotationIndex);
                Plaintext decrypted;
                const auto decryptResult = context->Decrypt(keyPair.secretKey, rotated, &decrypted);
                result.decryptValid = decryptResult.isValid;
                if (!result.decryptValid) {
                    throw std::runtime_error("decryption reported an invalid result");
                }
                result.permutation = decrypted->GetPackedValue();
                result.isPermutation = IsFrozenLabelPermutation(result.permutation, batchSize);
                if (!result.isPermutation) {
                    throw std::runtime_error("decrypted values are not the frozen label permutation");
                }
                result.evaluationSucceeded = true;
            }
            catch (const std::exception& exception) {
                result.error = exception.what();
                allProbesValid = false;
            }
            results.push_back(std::move(result));
        }

        std::ofstream output(outputPath, std::ios::out | std::ios::trunc);
        if (!output) {
            std::cerr << "cannot open output: " << outputPath << '\n';
            return 4;
        }
        output << "{\n";
        output << "  \"status\": \"measured-openfhe\",\n";
        output << "  \"scheme\": \"BFVRNS\",\n";
        output << "  \"ring_dimension\": " << ringDim << ",\n";
        output << "  \"plaintext_modulus\": " << plaintextModulus << ",\n";
        output << "  \"batch_size\": " << batchSize << ",\n";
        output << "  \"multiplicative_depth\": " << multiplicativeDepth << ",\n";
        output << "  \"eval_add_count\": " << contextEvalAddCount << ",\n";
        output << "  \"key_switch_count\": " << contextKeySwitchCount << ",\n";
        output << "  \"two_row_hypothesis_only\": false,\n";
        output << "  \"probes\": [\n";
        for (std::size_t resultIndex = 0; resultIndex < results.size(); ++resultIndex) {
            const auto& result = results[resultIndex];
            output << "    {\"index\": " << result.index
                   << ", \"key_generated\": " << (result.keyGenerated ? "true" : "false")
                   << ", \"evaluation_succeeded\": "
                   << (result.evaluationSucceeded ? "true" : "false")
                   << ", \"decrypt_valid\": " << (result.decryptValid ? "true" : "false")
                   << ", \"is_permutation\": " << (result.isPermutation ? "true" : "false")
                   << ", \"error\": \"" << dynamic_cssc::JsonEscape(result.error)
                   << "\", \"decrypted_permutation\": ";
            WriteVector(output, result.permutation);
            output << '}';
            if (resultIndex + 1 != results.size()) {
                output << ',';
            }
            output << '\n';
        }
        output << "  ]\n";
        output << "}\n";
        std::cout << outputPath << '\n';
        if (!allProbesValid) {
            std::cerr << "one or more rotation probes failed validation\n";
            return 5;
        }
        return 0;
    }
    catch (const std::exception& exception) {
        std::cerr << "rotation_probe failed: " << exception.what() << '\n';
        return 1;
    }
}
