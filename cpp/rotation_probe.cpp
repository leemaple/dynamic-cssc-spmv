#include "openfhe.h"

#include <cstdint>
#include <fstream>
#include <iostream>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "include/args.hpp"

using namespace lbcrypto;

namespace {

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

}  // namespace

int main(int argc, char** argv) {
    try {
        const auto args = dynamic_cssc::ParseArgs(argc, argv);
        const auto outputPath = dynamic_cssc::GetString(args, "output", "rotation_layout.json");
        const auto ringDim = dynamic_cssc::GetUInt(args, "ring-dim", 8192);
        const auto plaintextModulus = dynamic_cssc::GetUInt(args, "plaintext-modulus", 65537);
        const auto batchSize = dynamic_cssc::GetUInt(args, "batch-size", ringDim);
        const auto multiplicativeDepth = dynamic_cssc::GetUInt(args, "multiplicative-depth", 2);
        const auto requested = dynamic_cssc::ParseIndices(dynamic_cssc::GetString(
            args,
            "indices",
            "1,-1,2,-2,4,-4,8,-8,16,-16,32,-32,64,-64,128,-128,256,-256,512,-512,1024,-1024,2048,-2048,4095,-4095,4096"));

        if (plaintextModulus <= batchSize) {
            std::cerr << "plaintext modulus must exceed batch size so P0a labels remain unique\n";
            return 2;
        }

        auto context = MakeContext(ringDim, plaintextModulus, batchSize, multiplicativeDepth);
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
            std::string error;
            std::vector<int64_t> permutation;
        };
        std::vector<ProbeResult> results;
        results.reserve(requested.size());

        for (const auto rotationIndex : requested) {
            ProbeResult result{rotationIndex, false, false, "", {}};
            try {
                context->EvalRotateKeyGen(keyPair.secretKey, {rotationIndex});
                result.keyGenerated = true;
                const auto rotated = context->EvalRotate(ciphertext, rotationIndex);
                Plaintext decrypted;
                context->Decrypt(keyPair.secretKey, rotated, &decrypted);
                decrypted->SetLength(batchSize);
                result.permutation = decrypted->GetPackedValue();
                if (result.permutation.size() > batchSize) {
                    result.permutation.resize(batchSize);
                }
                result.evaluationSucceeded = true;
            }
            catch (const std::exception& exception) {
                result.error = exception.what();
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
        output << "  \"two_row_hypothesis_only\": false,\n";
        output << "  \"probes\": [\n";
        for (std::size_t resultIndex = 0; resultIndex < results.size(); ++resultIndex) {
            const auto& result = results[resultIndex];
            output << "    {\"index\": " << result.index
                   << ", \"key_generated\": " << (result.keyGenerated ? "true" : "false")
                   << ", \"evaluation_succeeded\": "
                   << (result.evaluationSucceeded ? "true" : "false")
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
        return 0;
    }
    catch (const std::exception& exception) {
        std::cerr << "rotation_probe failed: " << exception.what() << '\n';
        return 1;
    }
}
