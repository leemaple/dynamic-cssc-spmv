#include "openfhe.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include "include/args.hpp"

using namespace lbcrypto;

namespace {

constexpr std::uint32_t kRingDimension = 8192;
constexpr std::uint64_t kPlaintextModulus = 65537;
constexpr std::uint32_t kBatchSize = 8192;
constexpr std::uint32_t kEffectiveSlots = 4096;
constexpr std::uint32_t kLogicalPayloadWidth = 127;
constexpr std::uint32_t kPhysicalSegmentWidth = 128;
constexpr std::uint32_t kMultiplicativeDepth = 2;
constexpr std::uint32_t kEstimatorEvalAddCount = 0;
constexpr std::uint32_t kEstimatorKeySwitchCount = 0;
constexpr std::uint32_t kReductionEvalAddCount = 7;
constexpr std::uint32_t kUnrelinearizedElementCount = 3;
constexpr std::uint32_t kRelinearizedElementCount = 2;
constexpr std::uint32_t kComponentCount = 2;
constexpr std::uint32_t kTailSegmentStart = 3968;
constexpr std::uint32_t kAntiAliasGlobalColumn = 8192;
constexpr std::array<std::int32_t, kReductionEvalAddCount> kReductionRotations = {1, 2, 4, 8, 16, 32, 64};
constexpr std::array<std::int64_t, 4> kExpectedResult = {4, 6, 20, -8};
constexpr char kOpenFHERepository[] = "https://github.com/openfheorg/openfhe-development.git";
constexpr char kOpenFHEVersion[] = "1.5.1";
constexpr char kOpenFHECommit[] = "1306d14f8c26bb6150d3e6ad54f28dfe1007689e";
constexpr char kExecutionBindingFormat[] = "dynamic-cssc-execution-binding-v1";
constexpr char kExecutionBindingVersion[] = "strong-witness-v1";
constexpr char kCloudProgramFormat[] = "dynamic-cssc-cloud-program-v1";
constexpr char kOutputPlanFormat[] = "dynamic-cssc-output-plan-v1";
constexpr char kStartMaskId[] = "segment-starts";

struct ComponentInput {
    std::string componentId;
    std::string outputBlockId;
    std::string valueInputId;
    std::string queryInputId;
    std::string f1mMaskInputId;
    std::string resultId;
    std::vector<std::int64_t> values;
    std::vector<std::int64_t> alignedQuery;
    std::vector<std::pair<std::uint32_t, std::uint32_t>> startToLogical;
};

void SetComponentIdentity(ComponentInput& component, std::uint32_t index) {
    component.componentId = "witness-component-" + std::to_string(index);
    component.outputBlockId = "page-000000";
    component.valueInputId = component.componentId + "-values";
    component.queryInputId = component.componentId + "-query";
    component.f1mMaskInputId = component.componentId + "-f1m-mask";
    component.resultId = component.componentId + "-" + component.outputBlockId;
}

struct ExecutionTraceNode {
    std::string operation;
    std::string resultId;
    std::string ciphertextId;
    std::string leftId;
    std::string rightId;
    std::string maskId;
    std::string maskCiphertextId;
    std::string maskRole;
    std::int32_t logicalShift = 0;
    std::int32_t openfheIndex = 0;
};

struct F1MMasks {
    std::array<std::vector<std::int64_t>, kComponentCount> values;
    bool disjointMaskZero;
    bool zeroSumMask;
};

struct EvaluationResult {
    Ciphertext<DCRTPoly> maskedOutput;
    std::size_t unrelinearizedElementCount;
    std::size_t productElementCount;
};

struct WitnessResult {
    std::array<std::int64_t, 4> decryptedResult;
    std::array<std::size_t, kComponentCount> unrelinearizedProductElementCounts;
    std::array<std::size_t, kComponentCount> productElementCounts;
    bool decryptionsValid;
    bool productsRelinearized;
    bool antiAliasPassed;
    bool tailSegmentExercised;
    bool nonPowerOfTwoPayloadBoundaryExercised;
    bool paddingLaneZero;
    bool secondBatchingRowZero;
    bool disjointMaskZero;
    bool zeroSumMask;
    bool matchesExpected;
    std::vector<ExecutionTraceNode> executionTrace;
};

CryptoContext<DCRTPoly> MakeContext() {
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(kPlaintextModulus);
    parameters.SetMultiplicativeDepth(kMultiplicativeDepth);
    parameters.SetSecurityLevel(HEStd_128_classic);
    parameters.SetRingDim(kRingDimension);
    parameters.SetBatchSize(kBatchSize);
    parameters.SetEvalAddCount(kEstimatorEvalAddCount);
    parameters.SetKeySwitchCount(kEstimatorKeySwitchCount);
    parameters.SetKeySwitchTechnique(HYBRID);
    parameters.SetMultiplicationTechnique(HPSPOVERQLEVELED);

    auto context = GenCryptoContext(parameters);
    const auto cryptoParameters = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(
        context->GetCryptoParameters());
    if (!cryptoParameters || cryptoParameters->GetEvalAddCount() != kEstimatorEvalAddCount ||
        cryptoParameters->GetKeySwitchCount() != kEstimatorKeySwitchCount) {
        throw std::runtime_error("generated context does not preserve estimator counts 2/0/0");
    }
    context->Enable(PKE);
    context->Enable(KEYSWITCH);
    context->Enable(LEVELEDSHE);
    context->Enable(ADVANCEDSHE);
    return context;
}

void PutTerm(
    ComponentInput& component,
    std::uint32_t physicalSlot,
    std::uint32_t globalColumn,
    std::int64_t matrixValue,
    const std::vector<std::int64_t>& globalQuery) {
    if (physicalSlot >= kEffectiveSlots ||
        physicalSlot % kPhysicalSegmentWidth >= kLogicalPayloadWidth) {
        throw std::invalid_argument("term is outside a 127-lane segment payload");
    }
    component.values.at(physicalSlot) = matrixValue;
    component.alignedQuery.at(physicalSlot) = globalQuery.at(globalColumn);
}

std::array<ComponentInput, kComponentCount> MakeComponentInputs(
    const std::vector<std::int64_t>& globalQuery) {
    std::array<ComponentInput, kComponentCount> components;
    for (auto& component : components) {
        component.values.assign(kBatchSize, 0);
        component.alignedQuery.assign(kBatchSize, 0);
    }

    auto& base = components.at(0);
    SetComponentIdentity(base, 0);
    base.startToLogical = {{0, 0}, {128, 1}, {256, 2}, {kTailSegmentStart, 3}};
    PutTerm(base, 0, kAntiAliasGlobalColumn, -2, globalQuery);
    PutTerm(base, kLogicalPayloadWidth - 1, 7, 1, globalQuery);
    PutTerm(base, 128, 1, 6, globalQuery);
    PutTerm(base, 256, 2, 7, globalQuery);
    PutTerm(base, kTailSegmentStart, 3, -7, globalQuery);
    PutTerm(base, kTailSegmentStart + 1, 4, -1, globalQuery);

    auto& delta = components.at(1);
    SetComponentIdentity(delta, 1);
    delta.startToLogical = {{0, 0}, {128, 2}};
    PutTerm(delta, 0, 0, 1, globalQuery);
    PutTerm(delta, 128, 5, 7, globalQuery);
    PutTerm(delta, 129, 6, 6, globalQuery);
    return components;
}

std::uint64_t ReadOsRandomMod(std::ifstream& entropy) {
    constexpr auto maximum = std::numeric_limits<std::uint64_t>::max();
    constexpr auto cutoff = maximum - (maximum % kPlaintextModulus);
    std::uint64_t sample = 0;
    do {
        entropy.read(reinterpret_cast<char*>(&sample), sizeof(sample));
        if (!entropy) {
            throw std::runtime_error("failed to read the operating-system CSPRNG");
        }
    } while (sample >= cutoff);
    return sample % kPlaintextModulus;
}

F1MMasks MakeF1MMasks() {
    std::ifstream entropy("/dev/urandom", std::ios::in | std::ios::binary);
    if (!entropy) {
        throw std::runtime_error("cannot open the operating-system CSPRNG");
    }
    F1MMasks masks;
    for (auto& values : masks.values) {
        values.assign(kBatchSize, 0);
    }

    const auto rowZeroMask = ReadOsRandomMod(entropy);
    const auto rowTwoMask = ReadOsRandomMod(entropy);
    masks.values.at(0).at(0) = static_cast<std::int64_t>(rowZeroMask);
    masks.values.at(1).at(0) = static_cast<std::int64_t>(
        (kPlaintextModulus - rowZeroMask) % kPlaintextModulus);
    masks.values.at(0).at(256) = static_cast<std::int64_t>(rowTwoMask);
    masks.values.at(1).at(128) = static_cast<std::int64_t>(
        (kPlaintextModulus - rowTwoMask) % kPlaintextModulus);

    masks.disjointMaskZero = masks.values.at(0).at(128) == 0 &&
                             masks.values.at(0).at(kTailSegmentStart) == 0;
    masks.zeroSumMask =
        (static_cast<std::uint64_t>(masks.values.at(0).at(0)) +
         static_cast<std::uint64_t>(masks.values.at(1).at(0))) %
                kPlaintextModulus ==
            0 &&
        (static_cast<std::uint64_t>(masks.values.at(0).at(256)) +
         static_cast<std::uint64_t>(masks.values.at(1).at(128))) %
                kPlaintextModulus ==
            0;
    return masks;
}

EvaluationResult EvaluateComponent(
    const CryptoContext<DCRTPoly>& context,
    const PublicKey<DCRTPoly>& publicKey,
    const ComponentInput& component,
    const Plaintext& startMask,
    const std::vector<std::int64_t>& maskValues,
    std::vector<ExecutionTraceNode>& executionTrace) {
    const auto valuePlaintext = context->MakePackedPlaintext(component.values);
    const auto queryPlaintext = context->MakePackedPlaintext(component.alignedQuery);
    const auto maskPlaintext = context->MakePackedPlaintext(maskValues);
    const auto valueCiphertext = context->Encrypt(publicKey, valuePlaintext);
    const auto queryCiphertext = context->Encrypt(publicKey, queryPlaintext);
    const auto encryptedMask = context->Encrypt(publicKey, maskPlaintext);

    const auto product = context->EvalMultNoRelin(valueCiphertext, queryCiphertext);
    const auto productId = component.componentId + "-product";
    executionTrace.push_back(
        {"multiply-ciphertexts",
         productId,
         "",
         component.valueInputId,
         component.queryInputId});
    const auto unrelinearizedElementCount = product->GetElements().size();
    const auto relinearized = context->Relinearize(product);
    const auto productElementCount = relinearized->GetElements().size();
    auto reduced = relinearized;
    auto reducedId = component.componentId + "-relinearized";
    executionTrace.push_back({"relinearize", reducedId, productId});
    std::uint32_t span = 1;
    for (const auto rotation : kReductionRotations) {
        const auto rotated = context->EvalRotate(reduced, rotation);
        const auto rotatedId =
            component.componentId + "-rotate-" + std::to_string(rotation);
        executionTrace.push_back(
            {"rotate", rotatedId, reducedId, "", "", "", "", "", rotation, rotation});
        reduced = context->EvalAdd(reduced, rotated);
        const auto summedId = component.componentId + "-sum-" +
                              std::to_string(span + static_cast<std::uint32_t>(rotation));
        executionTrace.push_back(
            {"add-ciphertexts", summedId, "", reducedId, rotatedId});
        reducedId = summedId;
        span += static_cast<std::uint32_t>(rotation);
    }
    const auto unblinded = context->EvalMult(reduced, startMask);
    const auto selectedId = component.componentId + "-selected";
    executionTrace.push_back(
        {"multiply-plaintext-mask", selectedId, reducedId, "", "", kStartMaskId});
    const auto maskedOutput = context->EvalAdd(unblinded, encryptedMask);
    const auto maskedId = component.componentId + "-masked";
    executionTrace.push_back(
        {"add-f1m-mask",
         maskedId,
         selectedId,
         "",
         "",
         "",
         component.f1mMaskInputId,
         "opaque-zero-sum"});
    executionTrace.push_back({"return-result", component.resultId, maskedId});
    return {maskedOutput, unrelinearizedElementCount, productElementCount};
}

std::uint64_t NormalizeMod(std::int64_t value) {
    const auto modulus = static_cast<std::int64_t>(kPlaintextModulus);
    auto normalized = value % modulus;
    if (normalized < 0) {
        normalized += modulus;
    }
    return static_cast<std::uint64_t>(normalized);
}

std::int64_t CenteredLift(std::uint64_t value) {
    return value > kPlaintextModulus / 2
               ? static_cast<std::int64_t>(value) - static_cast<std::int64_t>(kPlaintextModulus)
               : static_cast<std::int64_t>(value);
}

bool IsSha256Digest(const std::string& value) {
    if (value.size() != 64) {
        return false;
    }
    return value.find_first_not_of("0123456789abcdef") == std::string::npos;
}

std::string RequireDigest(
    const std::unordered_map<std::string, std::string>& arguments,
    const std::string& key) {
    const auto iterator = arguments.find(key);
    if (iterator == arguments.end() || !IsSha256Digest(iterator->second)) {
        throw std::invalid_argument("--" + key + " must be a 64-character lowercase SHA-256 digest");
    }
    return iterator->second;
}

template <typename Value, std::size_t Size>
void WriteArray(std::ostream& output, const std::array<Value, Size>& values) {
    output << '[';
    for (std::size_t index = 0; index < values.size(); ++index) {
        if (index != 0) {
            output << ',';
        }
        output << values.at(index);
    }
    output << ']';
}

void WriteExecutionTrace(
    std::ostream& output,
    const std::vector<ExecutionTraceNode>& executionTrace) {
    output << "[\n";
    for (std::size_t index = 0; index < executionTrace.size(); ++index) {
        const auto& node = executionTrace.at(index);
        output << "    {";
        if (node.operation == "multiply-ciphertexts" ||
            node.operation == "add-ciphertexts") {
            output << "\"left_id\":\"" << dynamic_cssc::JsonEscape(node.leftId)
                   << "\",\"op\":\"" << node.operation << "\",\"result_id\":\""
                   << dynamic_cssc::JsonEscape(node.resultId) << "\",\"right_id\":\""
                   << dynamic_cssc::JsonEscape(node.rightId) << "\"";
        }
        else if (node.operation == "relinearize" ||
                 node.operation == "return-result") {
            output << "\"ciphertext_id\":\""
                   << dynamic_cssc::JsonEscape(node.ciphertextId) << "\",\"op\":\""
                   << node.operation << "\",\"result_id\":\""
                   << dynamic_cssc::JsonEscape(node.resultId) << "\"";
        }
        else if (node.operation == "rotate") {
            output << "\"ciphertext_id\":\""
                   << dynamic_cssc::JsonEscape(node.ciphertextId)
                   << "\",\"logical_shift\":" << node.logicalShift
                   << ",\"openfhe_index\":" << node.openfheIndex << ",\"op\":\"rotate\""
                   << ",\"result_id\":\"" << dynamic_cssc::JsonEscape(node.resultId)
                   << "\"";
        }
        else if (node.operation == "multiply-plaintext-mask") {
            output << "\"ciphertext_id\":\""
                   << dynamic_cssc::JsonEscape(node.ciphertextId) << "\",\"mask_id\":\""
                   << dynamic_cssc::JsonEscape(node.maskId)
                   << "\",\"op\":\"multiply-plaintext-mask\",\"result_id\":\""
                   << dynamic_cssc::JsonEscape(node.resultId) << "\"";
        }
        else if (node.operation == "add-f1m-mask") {
            output << "\"ciphertext_id\":\""
                   << dynamic_cssc::JsonEscape(node.ciphertextId)
                   << "\",\"mask_ciphertext_id\":\""
                   << dynamic_cssc::JsonEscape(node.maskCiphertextId)
                   << "\",\"mask_role\":\"" << dynamic_cssc::JsonEscape(node.maskRole)
                   << "\",\"op\":\"add-f1m-mask\",\"result_id\":\""
                   << dynamic_cssc::JsonEscape(node.resultId) << "\"";
        }
        else {
            throw std::runtime_error("cannot serialize unsupported execution trace operation");
        }
        output << '}';
        if (index + 1 != executionTrace.size()) {
            output << ',';
        }
        output << '\n';
    }
    output << "  ]";
}

void WriteRealizedContract(
    std::ostream& output,
    const std::array<ComponentInput, kComponentCount>& components,
    const std::vector<std::int64_t>& startMaskValues,
    const std::vector<ExecutionTraceNode>& executionTrace) {
    if (startMaskValues.size() != kBatchSize) {
        throw std::runtime_error("realized start mask has the wrong physical length");
    }

    std::vector<std::uint32_t> leaderPositions;
    for (std::uint32_t slot = 0; slot < kEffectiveSlots; ++slot) {
        const auto value = startMaskValues.at(slot);
        if (value == 1) {
            leaderPositions.push_back(slot);
        }
        else if (value != 0) {
            throw std::runtime_error("realized selection mask is not binary");
        }
    }

    using InputDeclaration = std::pair<std::string, std::string>;
    std::vector<InputDeclaration> inputDeclarations;
    std::vector<const ComponentInput*> sortedComponents;
    for (const auto& component : components) {
        if (component.values.size() != kBatchSize ||
            component.alignedQuery.size() != kBatchSize) {
            throw std::runtime_error("realized component has the wrong physical length");
        }
        inputDeclarations.emplace_back(component.f1mMaskInputId, "f1m-mask");
        inputDeclarations.emplace_back(component.queryInputId, "query");
        inputDeclarations.emplace_back(component.valueInputId, "value");
        sortedComponents.push_back(&component);
    }
    std::sort(inputDeclarations.begin(), inputDeclarations.end());
    std::sort(
        sortedComponents.begin(),
        sortedComponents.end(),
        [](const ComponentInput* left, const ComponentInput* right) {
            return std::pair<std::string, std::string>{left->componentId, left->outputBlockId} <
                   std::pair<std::string, std::string>{right->componentId, right->outputBlockId};
        });

    std::vector<std::pair<std::int32_t, std::int32_t>> realizedRotations;
    std::vector<std::string> resultIds;
    for (const auto& node : executionTrace) {
        if (node.operation == "rotate") {
            realizedRotations.emplace_back(node.logicalShift, node.openfheIndex);
        }
        else if (node.operation == "return-result") {
            resultIds.push_back(node.resultId);
        }
    }
    std::sort(realizedRotations.begin(), realizedRotations.end());
    realizedRotations.erase(
        std::unique(realizedRotations.begin(), realizedRotations.end()),
        realizedRotations.end());

    output << "  \"realized_contract\": {\n";
    output << "    \"execution_binding\": {\"format\":\""
           << kExecutionBindingFormat << "\",\"version_id\":\""
           << kExecutionBindingVersion << "\"},\n";
    output << "    \"cloud_program\": {\n";
    output << "      \"format\": \"" << kCloudProgramFormat << "\",\n";
    output << "      \"slot_count\": " << kEffectiveSlots << ",\n";
    output << "      \"ciphertext_inputs\": [\n";
    for (std::size_t index = 0; index < inputDeclarations.size(); ++index) {
        const auto& [ciphertextId, role] = inputDeclarations.at(index);
        output << "        {\"ciphertext_id\":\""
               << dynamic_cssc::JsonEscape(ciphertextId) << "\",\"length\":"
               << kEffectiveSlots << ",\"role\":\"" << dynamic_cssc::JsonEscape(role)
               << "\"}";
        output << (index + 1 == inputDeclarations.size() ? "\n" : ",\n");
    }
    output << "      ],\n";
    output << "      \"plaintext_masks\": [{\"length\":" << kEffectiveSlots
           << ",\"mask_id\":\"" << kStartMaskId
           << "\",\"role\":\"selection\",\"leader_positions\":[";
    for (std::size_t index = 0; index < leaderPositions.size(); ++index) {
        if (index != 0) {
            output << ',';
        }
        output << leaderPositions.at(index);
    }
    output << "]}],\n";
    output << "      \"rotation_catalog\": [";
    for (std::size_t index = 0; index < realizedRotations.size(); ++index) {
        if (index != 0) {
            output << ',';
        }
        const auto& [logicalShift, openfheIndex] = realizedRotations.at(index);
        output << "{\"logical_shift\":" << logicalShift << ",\"openfhe_index\":"
               << openfheIndex << '}';
    }
    output << "],\n";
    output << "      \"result_ids\": [";
    for (std::size_t index = 0; index < resultIds.size(); ++index) {
        if (index != 0) {
            output << ',';
        }
        output << '"' << dynamic_cssc::JsonEscape(resultIds.at(index)) << '"';
    }
    output << "]\n";
    output << "    },\n";
    output << "    \"output_plan\": {\n";
    output << "      \"format\": \"" << kOutputPlanFormat << "\",\n";
    output << "      \"logical_output_size\": " << kExpectedResult.size() << ",\n";
    output << "      \"slot_count\": " << kEffectiveSlots << ",\n";
    output << "      \"shares\": [\n";
    for (std::size_t componentIndex = 0; componentIndex < sortedComponents.size();
         ++componentIndex) {
        const auto& component = *sortedComponents.at(componentIndex);
        auto mappings = component.startToLogical;
        std::sort(mappings.begin(), mappings.end());
        output << "        {\"component_id\":\""
               << dynamic_cssc::JsonEscape(component.componentId)
               << "\",\"output_block_id\":\""
               << dynamic_cssc::JsonEscape(component.outputBlockId)
               << "\",\"slot_to_logical\":[";
        for (std::size_t mappingIndex = 0; mappingIndex < mappings.size(); ++mappingIndex) {
            if (mappingIndex != 0) {
                output << ',';
            }
            output << '[' << mappings.at(mappingIndex).first << ','
                   << mappings.at(mappingIndex).second << ']';
        }
        output << "]}";
        output << (componentIndex + 1 == sortedComponents.size() ? "\n" : ",\n");
    }
    output << "      ]\n";
    output << "    }\n";
    output << "  }";
}

void WriteWitness(
    const std::string& outputPath,
    const std::string& cloudProgramDigest,
    const std::string& outputPlanDigest,
    const std::string& executionBindingDigest,
    const WitnessResult& result,
    const std::array<ComponentInput, kComponentCount>& components,
    const std::vector<std::int64_t>& startMaskValues) {
    std::ofstream output(outputPath, std::ios::out | std::ios::trunc);
    if (!output) {
        throw std::runtime_error("cannot open output: " + outputPath);
    }
    output << "{\n";
    output << "  \"schema_version\": \"strong-packed-coo-witness-v1\",\n";
    output << "  \"status\": \"" << (result.matchesExpected ? "pass" : "fail") << "\",\n";
    output << "  \"evidence_scope\": "
           << "\"fixed-stride-primitive-correctness-only-pinned-openfhe\",\n";
    output << "  \"bindings\": {\n";
    output << "    \"cloud_program_digest\": \"" << cloudProgramDigest << "\",\n";
    output << "    \"output_plan_digest\": \"" << outputPlanDigest << "\",\n";
    output << "    \"execution_binding_digest\": \"" << executionBindingDigest << "\"\n";
    output << "  },\n";
    output << "  \"adapter\": {\n";
    output << "    \"typed_slot_count\": 4096,\n";
    output << "    \"physical_batch_size\": 8192,\n";
    output << "    \"second_batching_row_zero\": "
           << (result.secondBatchingRowZero ? "true" : "false") << "\n";
    output << "  },\n";
    output << "  \"openfhe\": {\n";
    output << "    \"repository\": \"" << kOpenFHERepository << "\",\n";
    output << "    \"version\": \"" << kOpenFHEVersion << "\",\n";
    output << "    \"commit\": \"" << kOpenFHECommit << "\",\n";
    output << "    \"scheme\": \"BFVRNS\",\n";
    output << "    \"ring_dimension\": " << kRingDimension << ",\n";
    output << "    \"plaintext_modulus\": " << kPlaintextModulus << ",\n";
    output << "    \"batch_size\": " << kBatchSize << ",\n";
    output << "    \"effective_first_row_slots\": " << kEffectiveSlots << ",\n";
    output << "    \"multiplicative_depth\": " << kMultiplicativeDepth << ",\n";
    output << "    \"eval_add_count\": " << kEstimatorEvalAddCount << ",\n";
    output << "    \"key_switch_count\": " << kEstimatorKeySwitchCount << "\n";
    output << "  },\n";
    output << "  \"circuit\": {\n";
    output << "    \"component_count\": " << kComponentCount << ",\n";
    output << "    \"logical_payload_width\": " << kLogicalPayloadWidth << ",\n";
    output << "    \"physical_segment_width\": " << kPhysicalSegmentWidth << ",\n";
    output << "    \"padding_lanes_per_segment\": "
           << (kPhysicalSegmentWidth - kLogicalPayloadWidth) << ",\n";
    output << "    \"reduction_rotation_indices\": [1,2,4,8,16,32,64],\n";
    output << "    \"reduction_eval_add_count_per_component\": "
           << kReductionEvalAddCount << ",\n";
    output << "    \"start_mask_applications_per_component\": 1\n";
    output << "  },\n";
    WriteRealizedContract(output, components, startMaskValues, result.executionTrace);
    output << ",\n";
    output << "  \"execution_trace\": ";
    WriteExecutionTrace(output, result.executionTrace);
    output << ",\n";
    output << "  \"correctness\": {\n";
    output << "    \"expected_centered_result\": ";
    WriteArray(output, kExpectedResult);
    output << ",\n    \"decrypted_centered_result\": ";
    WriteArray(output, result.decryptedResult);
    output << ",\n    \"matches_expected\": " << (result.matchesExpected ? "true" : "false") << ",\n";
    output << "    \"decryptions_valid\": " << (result.decryptionsValid ? "true" : "false") << ",\n";
    output << "    \"products_relinearized\": " << (result.productsRelinearized ? "true" : "false") << ",\n";
    output << "    \"unrelinearized_product_element_counts\": ";
    WriteArray(output, result.unrelinearizedProductElementCounts);
    output << ",\n";
    output << "    \"product_element_counts\": ";
    WriteArray(output, result.productElementCounts);
    output << ",\n    \"global_column_index\": " << kAntiAliasGlobalColumn << ",\n";
    output << "    \"global_column_index_anti_alias\": " << (result.antiAliasPassed ? "true" : "false") << ",\n";
    output << "    \"tail_segment_start\": " << kTailSegmentStart << ",\n";
    output << "    \"tail_segment_exercised\": " << (result.tailSegmentExercised ? "true" : "false") << ",\n";
    output << "    \"non_power_of_two_payload_boundary_exercised\": "
           << (result.nonPowerOfTwoPayloadBoundaryExercised ? "true" : "false")
           << ",\n";
    output << "    \"padding_lane_zero\": " << (result.paddingLaneZero ? "true" : "false")
           << "\n";
    output << "  },\n";
    output << "  \"f1m\": {\n";
    output << "    \"mode\": \"encrypted-one-time-zero-sum\",\n";
    output << "    \"mask_scope\": \"logical-coordinate-overlap-only\",\n";
    output << "    \"encrypted_mask_ciphertext_count\": 2,\n";
    output << "    \"overlap_coordinate_count\": 2,\n";
    output << "    \"disjoint_mask_zero\": " << (result.disjointMaskZero ? "true" : "false") << ",\n";
    output << "    \"zero_sum_mask\": " << (result.zeroSumMask ? "true" : "false") << ",\n";
    output << "    \"mask_values_redacted\": true\n";
    output << "  },\n";
    output << "  \"claims\": {\n";
    output << "    \"gate_eligible\": false,\n";
    output << "    \"complete_cost_claim_allowed\": false,\n";
    output << "    \"formal_parameter_claim_allowed\": false,\n";
    output << "    \"end_to_end_correctness_claim_allowed\": false,\n";
    output << "    \"security_claim_allowed\": false,\n";
    output << "    \"formal_correctness_claim\": false,\n";
    output << "    \"formal_security_claim\": false,\n";
    output << "    \"formal_performance_claim\": false,\n";
    output << "    \"mixed_workload_parameter_claim\": false\n";
    output << "  }\n";
    output << "}\n";
}

}  // namespace

int main(int argc, char** argv) {
    try {
        const auto arguments = dynamic_cssc::ParseArgs(argc, argv);
        const std::unordered_set<std::string> allowedArguments = {
            "output", "cloud-program-digest", "output-plan-digest", "execution-binding-digest"};
        if (argc != 9 || arguments.size() != allowedArguments.size()) {
            throw std::invalid_argument("exactly four distinct named arguments are required");
        }
        for (const auto& [key, value] : arguments) {
            static_cast<void>(value);
            if (allowedArguments.find(key) == allowedArguments.end()) {
                throw std::invalid_argument("unknown argument: --" + key);
            }
        }
        const auto outputPath = dynamic_cssc::GetString(arguments, "output", "");
        if (outputPath.empty()) {
            throw std::invalid_argument("--output is required");
        }
        const auto cloudProgramDigest = RequireDigest(arguments, "cloud-program-digest");
        const auto outputPlanDigest = RequireDigest(arguments, "output-plan-digest");
        const auto executionBindingDigest = RequireDigest(arguments, "execution-binding-digest");

        const auto context = MakeContext();
        const auto keyPair = context->KeyGen();
        if (!keyPair.good()) {
            throw std::runtime_error("key generation failed");
        }
        context->EvalMultKeyGen(keyPair.secretKey);
        context->EvalRotateKeyGen(
            keyPair.secretKey,
            std::vector<std::int32_t>(
                kReductionRotations.begin(), kReductionRotations.end()));

        std::vector<std::int64_t> globalQuery(kAntiAliasGlobalColumn + 1, 1);
        globalQuery.at(0) = 1;
        globalQuery.at(kAntiAliasGlobalColumn) = -1;
        const auto components = MakeComponentInputs(globalQuery);
        const bool antiAliasPassed =
            components.at(0).alignedQuery.at(0) == globalQuery.at(kAntiAliasGlobalColumn) &&
            components.at(1).alignedQuery.at(0) == globalQuery.at(0) &&
            globalQuery.at(kAntiAliasGlobalColumn) != globalQuery.at(0);
        const bool nonPowerOfTwoPayloadBoundaryExercised =
            components.at(0).values.at(kLogicalPayloadWidth - 1) == 1 &&
            components.at(0).alignedQuery.at(kLogicalPayloadWidth - 1) == globalQuery.at(7);
        bool paddingLaneZero = true;
        for (const auto& component : components) {
            for (std::uint32_t padding = kPhysicalSegmentWidth - 1;
                 padding < kEffectiveSlots;
                 padding += kPhysicalSegmentWidth) {
                paddingLaneZero = paddingLaneZero && component.values.at(padding) == 0 &&
                                  component.alignedQuery.at(padding) == 0;
            }
        }

        std::vector<std::int64_t> startMaskValues(kBatchSize, 0);
        for (std::uint32_t start = 0; start < kEffectiveSlots;
             start += kPhysicalSegmentWidth) {
            startMaskValues.at(start) = 1;
        }
        const auto startMask = context->MakePackedPlaintext(startMaskValues);
        const auto masks = MakeF1MMasks();
        bool secondBatchingRowZero = true;
        for (std::uint32_t slot = kEffectiveSlots; slot < kBatchSize; ++slot) {
            secondBatchingRowZero = secondBatchingRowZero && startMaskValues.at(slot) == 0;
            for (std::size_t componentIndex = 0; componentIndex < components.size();
                 ++componentIndex) {
                secondBatchingRowZero =
                    secondBatchingRowZero && components.at(componentIndex).values.at(slot) == 0 &&
                    components.at(componentIndex).alignedQuery.at(slot) == 0 &&
                    masks.values.at(componentIndex).at(slot) == 0;
            }
        }

        std::array<std::uint64_t, kExpectedResult.size()> modularResult = {0, 0, 0, 0};
        std::array<std::size_t, kComponentCount> unrelinearizedProductElementCounts = {0, 0};
        std::array<std::size_t, kComponentCount> productElementCounts = {0, 0};
        std::vector<ExecutionTraceNode> executionTrace;
        executionTrace.reserve(38);
        bool decryptionsValid = true;
        for (std::size_t componentIndex = 0; componentIndex < components.size();
             ++componentIndex) {
            const auto evaluated = EvaluateComponent(
                context,
                keyPair.publicKey,
                components.at(componentIndex),
                startMask,
                masks.values.at(componentIndex),
                executionTrace);
            unrelinearizedProductElementCounts.at(componentIndex) =
                evaluated.unrelinearizedElementCount;
            productElementCounts.at(componentIndex) = evaluated.productElementCount;

            Plaintext decrypted;
            const auto decryption = context->Decrypt(
                keyPair.secretKey, evaluated.maskedOutput, &decrypted);
            decryptionsValid = decryptionsValid && decryption.isValid;
            if (!decryption.isValid) {
                continue;
            }
            decrypted->SetLength(kBatchSize);
            const auto lanes = decrypted->GetPackedValue();
            for (std::uint32_t slot = kEffectiveSlots; slot < kBatchSize; ++slot) {
                secondBatchingRowZero =
                    secondBatchingRowZero && NormalizeMod(lanes.at(slot)) == 0;
            }
            for (const auto& [start, logical] : components.at(componentIndex).startToLogical) {
                modularResult.at(logical) =
                    (modularResult.at(logical) + NormalizeMod(lanes.at(start))) %
                    kPlaintextModulus;
            }
        }

        std::array<std::int64_t, kExpectedResult.size()> decryptedResult = {0, 0, 0, 0};
        for (std::size_t index = 0; index < modularResult.size(); ++index) {
            decryptedResult.at(index) = CenteredLift(modularResult.at(index));
        }
        const bool productsRelinearized =
            unrelinearizedProductElementCounts.at(0) == kUnrelinearizedElementCount &&
            unrelinearizedProductElementCounts.at(1) == kUnrelinearizedElementCount &&
            productElementCounts.at(0) == kRelinearizedElementCount &&
            productElementCounts.at(1) == kRelinearizedElementCount;
        const bool tailSegmentExercised =
            components.at(0).startToLogical.back() ==
                std::pair<std::uint32_t, std::uint32_t>{kTailSegmentStart, 3} &&
            decryptedResult.at(3) == kExpectedResult.at(3);
        const bool checksPassed = decryptionsValid && productsRelinearized && antiAliasPassed &&
                                  tailSegmentExercised &&
                                  nonPowerOfTwoPayloadBoundaryExercised && paddingLaneZero &&
                                  secondBatchingRowZero && masks.disjointMaskZero &&
                                  masks.zeroSumMask && executionTrace.size() == 38 &&
                                  decryptedResult == kExpectedResult;
        const WitnessResult result = {
            decryptedResult,
            unrelinearizedProductElementCounts,
            productElementCounts,
            decryptionsValid,
            productsRelinearized,
            antiAliasPassed,
            tailSegmentExercised,
            nonPowerOfTwoPayloadBoundaryExercised,
            paddingLaneZero,
            secondBatchingRowZero,
            masks.disjointMaskZero,
            masks.zeroSumMask,
            checksPassed,
            executionTrace};
        WriteWitness(
            outputPath,
            cloudProgramDigest,
            outputPlanDigest,
            executionBindingDigest,
            result,
            components,
            startMaskValues);
        std::cout << outputPath << '\n';
        return checksPassed ? 0 : 5;
    }
    catch (const std::exception& exception) {
        std::cerr << "strong_packed_coo_witness failed: " << exception.what() << '\n';
        return 1;
    }
}
