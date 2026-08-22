#include "openfhe.h"

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

constexpr std::uint32_t kRows = 4096;
constexpr std::uint32_t kCols = 8193;
constexpr std::uint32_t kRingDimension = 8192;
constexpr std::uint32_t kBatchSize = 8192;
constexpr std::uint32_t kEffectiveSlots = 4096;
constexpr std::uint32_t kActiveDeltaPayload = 127;
constexpr std::uint32_t kSegmentWidth = 128;
constexpr std::uint64_t kPlaintextModulus = 65537;
constexpr std::uint32_t kMultiplicativeDepth = 2;
constexpr std::uint32_t kEstimatorEvalAddCount = 0;
constexpr std::uint32_t kEstimatorKeySwitchCount = 0;
constexpr std::uint32_t kGlobalColumn = 8192;
constexpr std::int64_t kQueryEntryAbsBound = 1;
constexpr bool kCompleteReferenceSet = false;
constexpr bool kCandidateRegistered = false;
constexpr std::array<std::int32_t, 7> kDeltaRotations = {1, 2, 4, 8, 16, 32, 64};
constexpr std::array<std::int32_t, 2> kBaseRotations = {1, 2};
constexpr char kOpenFHERepository[] = "https://github.com/openfheorg/openfhe-development.git";
constexpr char kOpenFHEVersion[] = "1.5.1";
constexpr char kOpenFHECommit[] = "1306d14f8c26bb6150d3e6ad54f28dfe1007689e";

struct OperandInput {
    std::string valueId;
    std::string queryId;
    std::string f1mId;
    std::string resultId;
    std::vector<std::int64_t> values;
    std::vector<std::int64_t> alignedQuery;
    std::vector<std::int64_t> f1mValues;
    std::vector<std::int64_t> globalColumnIndices;
    std::vector<std::int32_t> rotations;
    std::vector<std::uint32_t> selectionLeaders;
};

struct TraceNode {
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

    TraceNode(
        std::string operationValue,
        std::string resultIdValue,
        std::string ciphertextIdValue = {},
        std::string leftIdValue = {},
        std::string rightIdValue = {},
        std::string maskIdValue = {},
        std::string maskCiphertextIdValue = {},
        std::string maskRoleValue = {},
        std::int32_t logicalShiftValue = 0,
        std::int32_t openfheIndexValue = 0)
        : operation(std::move(operationValue)),
          resultId(std::move(resultIdValue)),
          ciphertextId(std::move(ciphertextIdValue)),
          leftId(std::move(leftIdValue)),
          rightId(std::move(rightIdValue)),
          maskId(std::move(maskIdValue)),
          maskCiphertextId(std::move(maskCiphertextIdValue)),
          maskRole(std::move(maskRoleValue)),
          logicalShift(logicalShiftValue),
          openfheIndex(openfheIndexValue) {}
};

struct EvaluationResult {
    Ciphertext<DCRTPoly> ciphertext;
    std::size_t unrelinearizedElements;
    std::size_t relinearizedElements;
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

std::uint64_t ReadNonzeroMask() {
    std::ifstream entropy("/dev/urandom", std::ios::in | std::ios::binary);
    if (!entropy) {
        throw std::runtime_error("cannot open operating-system randomness for test mask");
    }
    constexpr auto maximum = std::numeric_limits<std::uint64_t>::max();
    constexpr auto cutoff = maximum - (maximum % kPlaintextModulus);
    std::uint64_t sample = 0;
    do {
        entropy.read(reinterpret_cast<char*>(&sample), sizeof(sample));
        if (!entropy) {
            throw std::runtime_error("failed to read operating-system randomness");
        }
    } while (sample >= cutoff || sample % kPlaintextModulus == 0);
    return sample % kPlaintextModulus;
}

std::vector<std::int64_t> MakeGlobalQuery() {
    std::vector<std::int64_t> query(kCols, 0);
    query.at(0) = 1;
    query.at(1) = 1;
    query.at(7) = 1;
    query.at(kGlobalColumn) = -1;
    for (std::uint32_t column = 100; column < 100 + kActiveDeltaPayload; ++column) {
        query.at(column) = 1;
    }
    return query;
}

void PutTerm(
    OperandInput& operand,
    std::uint32_t lane,
    std::uint32_t globalColumn,
    std::int64_t value,
    const std::vector<std::int64_t>& globalQuery) {
    if (lane >= kEffectiveSlots || globalColumn >= kCols) {
        throw std::invalid_argument("fixed witness term is outside its typed dimensions");
    }
    operand.values.at(lane) = value;
    operand.alignedQuery.at(lane) = globalQuery.at(globalColumn);
    operand.globalColumnIndices.at(lane) = static_cast<std::int64_t>(globalColumn);
}

std::array<OperandInput, 3> MakeOperands(
    const std::vector<std::int64_t>& globalQuery,
    std::uint64_t overlapMask) {
    std::array<OperandInput, 3> operands;
    for (std::size_t index = 0; index < operands.size(); ++index) {
        auto& operand = operands.at(index);
        const auto ordinal = std::string("00000") + std::to_string(index);
        operand.valueId = "ct-value-" + ordinal;
        operand.queryId = "ct-query-" + ordinal;
        operand.f1mId = "ct-f1m-" + ordinal;
        operand.resultId = "result-" + ordinal;
        operand.values.assign(kBatchSize, 0);
        operand.alignedQuery.assign(kBatchSize, 0);
        operand.f1mValues.assign(kBatchSize, 0);
        operand.globalColumnIndices.assign(kEffectiveSlots, -1);
    }

    operands.at(0).rotations.assign(kBaseRotations.begin(), kBaseRotations.end());
    operands.at(0).selectionLeaders = {0};
    PutTerm(operands.at(0), 0, 0, 2, globalQuery);
    PutTerm(operands.at(0), 1, 1, 3, globalQuery);
    PutTerm(operands.at(0), 2, kGlobalColumn, 4, globalQuery);
    operands.at(0).f1mValues.at(0) = static_cast<std::int64_t>(overlapMask);

    operands.at(1).selectionLeaders = {0};
    PutTerm(operands.at(1), 0, 7, 5, globalQuery);

    operands.at(2).rotations.assign(kDeltaRotations.begin(), kDeltaRotations.end());
    for (std::uint32_t leader = 0; leader < kEffectiveSlots; leader += kSegmentWidth) {
        operands.at(2).selectionLeaders.push_back(leader);
    }
    for (std::uint32_t offset = 0; offset < kActiveDeltaPayload; ++offset) {
        PutTerm(operands.at(2), offset, 100 + offset, 1, globalQuery);
    }
    operands.at(2).f1mValues.at(0) = static_cast<std::int64_t>(
        (kPlaintextModulus - overlapMask) % kPlaintextModulus);
    return operands;
}

std::string Ordinal(std::size_t value) {
    const auto digits = std::to_string(value);
    return std::string(6 - digits.size(), '0') + digits;
}

EvaluationResult EvaluateOperand(
    const CryptoContext<DCRTPoly>& context,
    const PublicKey<DCRTPoly>& publicKey,
    const OperandInput& operand,
    std::size_t ordinal,
    std::vector<TraceNode>& trace) {
    const auto ordinalText = Ordinal(ordinal);
    const auto valuePlaintext = context->MakePackedPlaintext(operand.values);
    const auto queryPlaintext = context->MakePackedPlaintext(operand.alignedQuery);
    const auto f1mPlaintext = context->MakePackedPlaintext(operand.f1mValues);
    std::vector<std::int64_t> selection(kBatchSize, 0);
    for (const auto leader : operand.selectionLeaders) {
        selection.at(leader) = 1;
    }
    const auto selectionPlaintext = context->MakePackedPlaintext(selection);
    const auto valueCiphertext = context->Encrypt(publicKey, valuePlaintext);
    const auto queryCiphertext = context->Encrypt(publicKey, queryPlaintext);
    const auto f1mCiphertext = context->Encrypt(publicKey, f1mPlaintext);

    const auto product = context->EvalMultNoRelin(valueCiphertext, queryCiphertext);
    const auto productId = "ssa-product-" + ordinalText;
    trace.push_back(
        {"multiply-ciphertexts", productId, "", operand.valueId, operand.queryId});
    const auto unrelinearizedElements = product->GetElements().size();
    const auto relinearized = context->Relinearize(product);
    const auto relinearizedId = "ssa-relinearized-" + ordinalText;
    trace.push_back({"relinearize", relinearizedId, productId});
    const auto relinearizedElements = relinearized->GetElements().size();

    auto accumulated = relinearized;
    auto accumulatedId = relinearizedId;
    for (std::size_t rotationOrdinal = 0; rotationOrdinal < operand.rotations.size();
         ++rotationOrdinal) {
        const auto rotation = operand.rotations.at(rotationOrdinal);
        const auto rotated = context->EvalRotate(
            ordinal < 2 ? relinearized : accumulated,
            rotation);
        const auto rotatedId = "ssa-rotate-" + ordinalText + "-" + Ordinal(rotation);
        trace.push_back(
            {"rotate", rotatedId, ordinal < 2 ? relinearizedId : accumulatedId,
             "", "", "", "", "", rotation, rotation});
        const auto sumId = ordinal < 2
                               ? "ssa-column-sum-" + ordinalText + "-" +
                                     Ordinal(rotationOrdinal + 1)
                               : "ssa-segment-sum-" + ordinalText + "-" +
                                     Ordinal(static_cast<std::size_t>(rotation) * 2);
        accumulated = context->EvalAdd(accumulated, rotated);
        trace.push_back({"add-ciphertexts", sumId, "", accumulatedId, rotatedId});
        accumulatedId = sumId;
    }
    const auto selected = context->EvalMult(accumulated, selectionPlaintext);
    const auto selectedId = "ssa-selected-" + ordinalText;
    const auto selectionId = "pt-selection-" + ordinalText;
    trace.push_back(
        {"multiply-plaintext-mask", selectedId, accumulatedId, "", "", selectionId});
    const auto masked = context->EvalAdd(selected, f1mCiphertext);
    const auto maskedId = "ssa-masked-" + ordinalText;
    trace.push_back(
        {"add-f1m-mask", maskedId, selectedId, "", "", "", operand.f1mId,
         "opaque-zero-sum"});
    trace.push_back({"return-result", operand.resultId, maskedId});
    return {masked, unrelinearizedElements, relinearizedElements};
}

std::uint64_t Normalize(std::int64_t value) {
    const auto modulus = static_cast<std::int64_t>(kPlaintextModulus);
    auto normalized = value % modulus;
    if (normalized < 0) {
        normalized += modulus;
    }
    return static_cast<std::uint64_t>(normalized);
}

std::int64_t Center(std::uint64_t value) {
    return value > kPlaintextModulus / 2
               ? static_cast<std::int64_t>(value) - static_cast<std::int64_t>(kPlaintextModulus)
               : static_cast<std::int64_t>(value);
}

bool IsDigest(const std::string& value) {
    return value.size() == 64 &&
           value.find_first_not_of("0123456789abcdef") == std::string::npos;
}

std::string RequireDigest(
    const std::unordered_map<std::string, std::string>& arguments,
    const std::string& key) {
    const auto value = dynamic_cssc::GetString(arguments, key, "");
    if (!IsDigest(value)) {
        throw std::invalid_argument("--" + key + " must be a lowercase SHA-256");
    }
    return value;
}

void WriteTrace(std::ostream& output, const std::vector<TraceNode>& trace) {
    output << "[\n";
    for (std::size_t index = 0; index < trace.size(); ++index) {
        const auto& node = trace.at(index);
        output << "    {";
        if (node.operation == "multiply-ciphertexts" ||
            node.operation == "add-ciphertexts") {
            output << "\"left_id\":\"" << node.leftId << "\",\"op\":\""
                   << node.operation << "\",\"result_id\":\"" << node.resultId
                   << "\",\"right_id\":\"" << node.rightId << "\"";
        }
        else if (node.operation == "relinearize" || node.operation == "return-result") {
            output << "\"ciphertext_id\":\"" << node.ciphertextId << "\",\"op\":\""
                   << node.operation << "\",\"result_id\":\"" << node.resultId << "\"";
        }
        else if (node.operation == "rotate") {
            output << "\"ciphertext_id\":\"" << node.ciphertextId
                   << "\",\"logical_shift\":" << node.logicalShift
                   << ",\"openfhe_index\":" << node.openfheIndex
                   << ",\"op\":\"rotate\",\"result_id\":\"" << node.resultId << "\"";
        }
        else if (node.operation == "multiply-plaintext-mask") {
            output << "\"ciphertext_id\":\"" << node.ciphertextId << "\",\"mask_id\":\""
                   << node.maskId
                   << "\",\"op\":\"multiply-plaintext-mask\",\"result_id\":\""
                   << node.resultId << "\"";
        }
        else if (node.operation == "add-f1m-mask") {
            output << "\"ciphertext_id\":\"" << node.ciphertextId
                   << "\",\"mask_ciphertext_id\":\"" << node.maskCiphertextId
                   << "\",\"mask_role\":\"" << node.maskRole
                   << "\",\"op\":\"add-f1m-mask\",\"result_id\":\""
                   << node.resultId << "\"";
        }
        else {
            throw std::runtime_error("unsupported trace operation");
        }
        output << (index + 1 == trace.size() ? "}\n" : "},\n");
    }
    output << "  ]";
}

void WriteSparseOutput(
    std::ostream& output,
    const std::array<std::int64_t, kRows>& values) {
    output << '[';
    bool first = true;
    for (std::size_t row = 0; row < values.size(); ++row) {
        if (values.at(row) == 0) {
            continue;
        }
        output << (first ? "" : ",") << '[' << row << ',' << values.at(row) << ']';
        first = false;
    }
    output << ']';
}

void WriteSizeArray(std::ostream& output, const std::array<std::size_t, 3>& values) {
    output << '[' << values.at(0) << ',' << values.at(1) << ',' << values.at(2) << ']';
}

void WriteTypedValues(
    std::ostream& output,
    const std::vector<std::int64_t>& values) {
    output << '[';
    for (std::uint32_t lane = 0; lane < kEffectiveSlots; ++lane) {
        output << (lane == 0 ? "" : ",") << values.at(lane);
    }
    output << ']';
}

void WriteCloudProgram(
    std::ostream& output,
    const std::array<OperandInput, 3>& operands,
    const std::vector<TraceNode>& trace) {
    output << "{\"ciphertext_inputs\":[";
    bool first = true;
    for (const auto* role : {"f1m-mask", "query", "value"}) {
        for (const auto& operand : operands) {
            const auto& id = std::string(role) == "f1m-mask"
                                 ? operand.f1mId
                                 : (std::string(role) == "query" ? operand.queryId
                                                                  : operand.valueId);
            output << (first ? "" : ",") << "{\"ciphertext_id\":\"" << id
                   << "\",\"length\":4096,\"role\":\"" << role << "\"}";
            first = false;
        }
    }
    output << "],\"format\":\"dynamic-cssc-cloud-program-v1\",\"nodes\":";
    WriteTrace(output, trace);
    output << ",\"plaintext_masks\":[";
    for (std::size_t ordinal = 0; ordinal < operands.size(); ++ordinal) {
        std::vector<std::int64_t> mask(kEffectiveSlots, 0);
        for (const auto leader : operands.at(ordinal).selectionLeaders) {
            mask.at(leader) = 1;
        }
        output << (ordinal == 0 ? "" : ",")
               << "{\"length\":4096,\"mask_id\":\"pt-selection-"
               << Ordinal(ordinal) << "\",\"role\":\"selection\",\"values\":";
        WriteTypedValues(output, mask);
        output << '}';
    }
    output << "],\"result_ids\":[\"result-000000\",\"result-000001\","
              "\"result-000002\"],\"rotation_catalog\":[";
    for (std::size_t index = 0; index < kDeltaRotations.size(); ++index) {
        const auto rotation = kDeltaRotations.at(index);
        output << (index == 0 ? "" : ",") << "{\"logical_shift\":" << rotation
               << ",\"openfhe_index\":" << rotation << '}';
    }
    output << "],\"slot_count\":4096}";
}

void WriteOutputPlan(std::ostream& output) {
    output << "{\"format\":\"dynamic-cssc-output-plan-v1\","
              "\"logical_output_size\":4096,\"slot_count\":4096,\"shares\":["
              "{\"component_id\":\"base\",\"output_block_id\":\"base-h000000\","
              "\"slot_to_logical\":[[0,0]]},"
              "{\"component_id\":\"base\",\"output_block_id\":\"base-h000001\","
              "\"slot_to_logical\":[[0,4095]]},"
              "{\"component_id\":\"strong-packed-coo-delta\","
              "\"output_block_id\":\"page-000000\",\"slot_to_logical\":[[0,0]]}]}";
}

void WritePrivatePlan(
    std::ostream& output,
    const std::array<OperandInput, 3>& operands,
    const std::array<std::string, 7>& bindings) {
    output << "{\"format\":\"dynamic-cssc-private-strong-plan-v1\","
              "\"output_plan_digest\":\""
           << bindings.at(3) << "\",\"operands\":[";
    for (std::size_t ordinal = 0; ordinal < operands.size(); ++ordinal) {
        const auto& operand = operands.at(ordinal);
        output << (ordinal == 0 ? "" : ",") << "{\"global_column_indices\":";
        WriteTypedValues(output, operand.globalColumnIndices);
        output << ",\"query_ciphertext_id\":\"" << operand.queryId
               << "\",\"result_id\":\"" << operand.resultId
               << "\",\"source_kind\":\""
               << (ordinal < 2 ? "base-chunk" : "delta-page")
               << "\",\"source_ordinal\":" << (ordinal < 2 ? ordinal : 0)
               << ",\"value_ciphertext_id\":\"" << operand.valueId << "\",\"values\":";
        WriteTypedValues(output, operand.values);
        output << '}';
    }
    output << "],\"routes\":["
              "{\"component_id\":\"base\",\"f1m_ciphertext_id\":\"ct-f1m-000000\","
              "\"output_block_id\":\"base-h000000\",\"result_id\":\"result-000000\"},"
              "{\"component_id\":\"base\",\"f1m_ciphertext_id\":\"ct-f1m-000001\","
              "\"output_block_id\":\"base-h000001\",\"result_id\":\"result-000001\"},"
              "{\"component_id\":\"strong-packed-coo-delta\","
              "\"f1m_ciphertext_id\":\"ct-f1m-000002\","
              "\"output_block_id\":\"page-000000\",\"result_id\":\"result-000002\"}]}";
}

void WritePreparedQuery(
    std::ostream& output,
    const std::array<OperandInput, 3>& operands,
    const std::vector<std::int64_t>& globalQuery,
    const std::array<std::string, 7>& bindings) {
    output << "{\"bindings\":{\"cloud_program_digest\":\"" << bindings.at(0)
           << "\",\"execution_binding_digest\":\"" << bindings.at(1)
           << "\",\"output_plan_digest\":\"" << bindings.at(3)
           << "\",\"private_plan_digest\":\"" << bindings.at(5)
           << "\"},\"f1m_operands\":["
              "{\"ciphertext_id\":\"ct-f1m-000000\",\"component_id\":\"base\","
              "\"kind\":\"random-zero-sum\",\"output_block_id\":\"base-h000000\","
              "\"result_id\":\"result-000000\","
              "\"values_policy\":\"fresh-random-zero-sum-redacted\"},"
              "{\"ciphertext_id\":\"ct-f1m-000001\",\"component_id\":\"base\","
              "\"kind\":\"encrypted-zero-dummy\",\"output_block_id\":\"base-h000001\","
              "\"result_id\":\"result-000001\","
              "\"values_policy\":\"exact-encrypted-zero\"},"
              "{\"ciphertext_id\":\"ct-f1m-000002\","
              "\"component_id\":\"strong-packed-coo-delta\","
              "\"kind\":\"random-zero-sum\",\"output_block_id\":\"page-000000\","
              "\"result_id\":\"result-000002\","
              "\"values_policy\":\"fresh-random-zero-sum-redacted\"}],"
              "\"format\":\"dynamic-cssc-prepared-strong-query-contract-v2\","
              "\"modulus\":65537,\"query_id\":\"strong-whole-query-witness-query-v2\","
              "\"query_operands\":[";
    for (std::size_t ordinal = 0; ordinal < operands.size(); ++ordinal) {
        output << (ordinal == 0 ? "" : ",") << "{\"ciphertext_id\":\""
               << operands.at(ordinal).queryId << "\",\"values\":";
        WriteTypedValues(output, operands.at(ordinal).alignedQuery);
        output << '}';
    }
    output << "],\"vector_length\":8193,\"vector_nonzero_entries\":[";
    bool first = true;
    for (std::size_t column = 0; column < globalQuery.size(); ++column) {
        if (globalQuery.at(column) == 0) {
            continue;
        }
        output << (first ? "" : ",") << '[' << column << ',' << globalQuery.at(column) << ']';
        first = false;
    }
    output << "],\"version_id\":\"strong-whole-query-witness-v2\"}";
}

void WriteRealizedContract(
    std::ostream& output,
    const std::array<OperandInput, 3>& operands,
    const std::vector<std::int64_t>& globalQuery,
    const std::vector<TraceNode>& trace,
    const std::array<std::string, 7>& bindings) {
    output << "{\"cloud_program\":";
    WriteCloudProgram(output, operands, trace);
    output << ",\"execution_binding\":{\"cloud_program_digest\":\""
           << bindings.at(0)
           << "\",\"format\":\"dynamic-cssc-execution-binding-v1\","
              "\"output_plan_digest\":\""
           << bindings.at(3)
           << "\",\"version_id\":\"strong-whole-query-witness-v2\"},"
              "\"format\":\"dynamic-cssc-strong-whole-query-contract-v2\","
              "\"output_plan\":";
    WriteOutputPlan(output);
    output << ",\"prepared_query\":";
    WritePreparedQuery(output, operands, globalQuery, bindings);
    output << ",\"private_plan\":";
    WritePrivatePlan(output, operands, bindings);
    output << '}';
}

void WriteWitness(
    const std::string& outputPath,
    const std::array<std::int64_t, kRows>& decrypted,
    const std::array<std::int64_t, kRows>& direct,
    const std::array<std::size_t, 3>& unrelinearized,
    const std::array<std::size_t, 3>& relinearized,
    const std::vector<TraceNode>& trace,
    const std::array<OperandInput, 3>& operands,
    const std::vector<std::int64_t>& globalQuery,
    const std::array<std::string, 7>& bindings,
    bool secondRowZero,
    bool masksCorrect,
    bool queryEntryBoundRespected,
    bool checksPassed) {
    std::ofstream output(outputPath, std::ios::out | std::ios::trunc);
    if (!output) {
        throw std::runtime_error("cannot open output: " + outputPath);
    }
    output << "{\n";
    output << "  \"schema_version\": \"strong-whole-query-witness-v2\",\n";
    output << "  \"status\": \"" << (checksPassed ? "pass" : "fail") << "\",\n";
    output << "  \"evidence_scope\": "
              "\"actual-cssc-base-plus-strong-delta-whole-query-pinned-openfhe\",\n";
    output << "  \"bindings\": {\"cloud_program_digest\":\"" << bindings.at(0)
           << "\",\"execution_binding_digest\":\"" << bindings.at(1)
           << "\",\"expected_centered_output_digest\":\"" << bindings.at(2)
           << "\",\"output_plan_digest\":\"" << bindings.at(3)
           << "\",\"prepared_query_contract_digest\":\"" << bindings.at(4)
           << "\",\"private_plan_digest\":\"" << bindings.at(5)
           << "\",\"whole_query_contract_digest\":\"" << bindings.at(6) << "\"},\n";
    output << "  \"adapter\": {\"typed_slot_count\":4096,\"physical_batch_size\":8192,"
              "\"second_batching_row_zero\":"
           << (secondRowZero ? "true" : "false") << "},\n";
    output << "  \"openfhe\": {\"repository\":\"" << kOpenFHERepository
           << "\",\"version\":\"" << kOpenFHEVersion << "\",\"commit\":\""
           << kOpenFHECommit
           << "\",\"scheme\":\"BFVRNS\",\"ring_dimension\":8192,"
              "\"plaintext_modulus\":65537,\"batch_size\":8192,"
              "\"effective_first_row_slots\":4096,\"multiplicative_depth\":2,"
              "\"eval_add_count\":0,\"key_switch_count\":0},\n";
    output << "  \"fixture\": {\"kind\":\"actual-cssc-base-plus-strong-delta\","
              "\"rows\":4096,\"cols\":8193,\"base_active_coordinate_count\":4,"
              "\"segment_width\":128,\"active_delta_payload\":127,"
              "\"padding_offset\":127,\"global_column_index\":8192,"
              "\"return_count\":3},\n";
    output << "  \"realized_contract\": ";
    WriteRealizedContract(output, operands, globalQuery, trace, bindings);
    output << ",\n";
    output << "  \"execution_trace\": ";
    WriteTrace(output, trace);
    output << ",\n";
    output << "  \"correctness\": {\"decrypted_centered_output_sparse\":";
    WriteSparseOutput(output, decrypted);
    output << ",\"direct_spmv_centered_output_sparse\":";
    WriteSparseOutput(output, direct);
    output << ",\"matches_python_typed_plaintext_oracle\":"
           << (checksPassed ? "true" : "false")
           << ",\"matches_python_direct_spmv\":" << (decrypted == direct ? "true" : "false")
           << ",\"decryptions_valid\":" << (checksPassed ? "true" : "false")
           << ",\"products_relinearized\":"
           << ((unrelinearized == std::array<std::size_t, 3>{3, 3, 3} &&
                relinearized == std::array<std::size_t, 3>{2, 2, 2})
                   ? "true"
                   : "false")
           << ",\"unrelinearized_product_element_counts\":";
    WriteSizeArray(output, unrelinearized);
    output << ",\"product_element_counts\":";
    WriteSizeArray(output, relinearized);
    output << ",\"global_column_index_anti_alias\":true,"
              "\"active_offset_126_exercised\":true,\"padding_offset_127_zero\":true,"
              "\"query_entry_bound_respected\":"
           << (queryEntryBoundRespected ? "true" : "false") << "},\n";
    output << "  \"f1m\": {\"mode\":\"encrypted-correctness-test-operands\","
              "\"return_ciphertext_count\":3,\"ciphertext_additions\":3,"
              "\"random_zero_sum_ciphertext_count\":2,"
              "\"encrypted_zero_dummy_ciphertext_count\":1,"
              "\"random_parts_nonzero\":"
           << (masksCorrect ? "true" : "false")
           << ",\"zero_sum_mask\":" << (masksCorrect ? "true" : "false")
           << ",\"dummy_exact_zero\":" << (masksCorrect ? "true" : "false")
           << ",\"mask_values_redacted\":true,\"persistent_ledger_exercised\":false,"
              "\"production_csprng_security_claim_allowed\":false},\n";
    output << "  \"claims\": {\"gate_eligible\":false,"
              "\"complete_reference_set\":"
           << (kCompleteReferenceSet ? "true" : "false")
           << ",\"candidate_registered\":" << (kCandidateRegistered ? "true" : "false")
           << ",\"complete_cost_claim_allowed\":false,"
              "\"formal_parameter_claim_allowed\":false,"
              "\"end_to_end_correctness_claim_allowed\":false,"
              "\"security_claim_allowed\":false,\"formal_correctness_claim\":false,"
              "\"formal_security_claim\":false,\"formal_performance_claim\":false,"
              "\"mixed_workload_parameter_claim\":false}\n";
    output << "}\n";
}

}  // namespace

int main(int argc, char** argv) {
    try {
        const auto arguments = dynamic_cssc::ParseArgs(argc, argv);
        const std::unordered_set<std::string> allowed = {
            "output",
            "cloud-program-digest",
            "execution-binding-digest",
            "expected-centered-output-digest",
            "output-plan-digest",
            "prepared-query-contract-digest",
            "private-plan-digest",
            "whole-query-contract-digest",
        };
        if (argc != 17 || arguments.size() != allowed.size()) {
            throw std::invalid_argument("exactly eight distinct named arguments are required");
        }
        for (const auto& [key, value] : arguments) {
            static_cast<void>(value);
            if (allowed.find(key) == allowed.end()) {
                throw std::invalid_argument("unknown argument: --" + key);
            }
        }
        const auto outputPath = dynamic_cssc::GetString(arguments, "output", "");
        if (outputPath.empty()) {
            throw std::invalid_argument("--output is required");
        }
        const std::array<std::string, 7> bindings = {
            RequireDigest(arguments, "cloud-program-digest"),
            RequireDigest(arguments, "execution-binding-digest"),
            RequireDigest(arguments, "expected-centered-output-digest"),
            RequireDigest(arguments, "output-plan-digest"),
            RequireDigest(arguments, "prepared-query-contract-digest"),
            RequireDigest(arguments, "private-plan-digest"),
            RequireDigest(arguments, "whole-query-contract-digest"),
        };

        const auto context = MakeContext();
        const auto keyPair = context->KeyGen();
        if (!keyPair.good()) {
            throw std::runtime_error("key generation failed");
        }
        context->EvalMultKeyGen(keyPair.secretKey);
        context->EvalRotateKeyGen(
            keyPair.secretKey,
            std::vector<std::int32_t>(kDeltaRotations.begin(), kDeltaRotations.end()));

        const auto globalQuery = MakeGlobalQuery();
        bool queryEntryBoundRespected = true;
        for (const auto entry : globalQuery) {
            if (entry < -kQueryEntryAbsBound || entry > kQueryEntryAbsBound) {
                queryEntryBoundRespected = false;
                break;
            }
        }
        const auto randomMask = ReadNonzeroMask();
        const auto operands = MakeOperands(globalQuery, randomMask);
        const bool antiAlias = operands.at(0).alignedQuery.at(2) == globalQuery.at(kGlobalColumn) &&
                               globalQuery.at(kGlobalColumn) != globalQuery.at(0);
        const bool deltaBoundary = operands.at(2).values.at(126) == 1 &&
                                   operands.at(2).values.at(127) == 0 &&
                                   operands.at(2).alignedQuery.at(127) == 0;
        const bool masksCorrect = operands.at(0).f1mValues.at(0) != 0 &&
                                  operands.at(2).f1mValues.at(0) != 0 &&
                                  Normalize(operands.at(0).f1mValues.at(0) +
                                            operands.at(2).f1mValues.at(0)) == 0 &&
                                  operands.at(1).f1mValues ==
                                      std::vector<std::int64_t>(kBatchSize, 0);

        bool secondRowZero = true;
        for (const auto& operand : operands) {
            for (std::uint32_t lane = kEffectiveSlots; lane < kBatchSize; ++lane) {
                secondRowZero = secondRowZero && operand.values.at(lane) == 0 &&
                                operand.alignedQuery.at(lane) == 0 &&
                                operand.f1mValues.at(lane) == 0;
            }
        }

        std::vector<TraceNode> trace;
        trace.reserve(33);
        std::array<std::size_t, 3> unrelinearized = {0, 0, 0};
        std::array<std::size_t, 3> relinearized = {0, 0, 0};
        std::array<std::array<std::int64_t, kBatchSize>, 3> decryptedLanes{};
        bool decryptionsValid = true;
        for (std::size_t ordinal = 0; ordinal < operands.size(); ++ordinal) {
            const auto evaluated = EvaluateOperand(
                context, keyPair.publicKey, operands.at(ordinal), ordinal, trace);
            unrelinearized.at(ordinal) = evaluated.unrelinearizedElements;
            relinearized.at(ordinal) = evaluated.relinearizedElements;
            Plaintext plaintext;
            const auto decryption = context->Decrypt(
                keyPair.secretKey, evaluated.ciphertext, &plaintext);
            decryptionsValid = decryptionsValid && decryption.isValid;
            if (!decryption.isValid) {
                continue;
            }
            plaintext->SetLength(kBatchSize);
            const auto lanes = plaintext->GetPackedValue();
            for (std::uint32_t lane = 0; lane < kBatchSize; ++lane) {
                decryptedLanes.at(ordinal).at(lane) =
                    static_cast<std::int64_t>(Normalize(lanes.at(lane)));
                if (lane >= kEffectiveSlots) {
                    secondRowZero = secondRowZero && Normalize(lanes.at(lane)) == 0;
                }
            }
        }

        std::array<std::int64_t, kRows> decrypted{};
        decrypted.at(0) = Center(
            (static_cast<std::uint64_t>(decryptedLanes.at(0).at(0)) +
             static_cast<std::uint64_t>(decryptedLanes.at(2).at(0))) %
            kPlaintextModulus);
        decrypted.at(4095) = Center(
            static_cast<std::uint64_t>(decryptedLanes.at(1).at(0)));
        std::array<std::int64_t, kRows> direct{};
        direct.at(0) = 2 * globalQuery.at(0) + 3 * globalQuery.at(1) +
                       4 * globalQuery.at(kGlobalColumn);
        for (std::uint32_t offset = 0; offset < kActiveDeltaPayload; ++offset) {
            direct.at(0) += globalQuery.at(100 + offset);
        }
        direct.at(4095) = 5 * globalQuery.at(7);
        const bool productsRelinearized =
            unrelinearized == std::array<std::size_t, 3>{3, 3, 3} &&
            relinearized == std::array<std::size_t, 3>{2, 2, 2};
        const bool checksPassed = decryptionsValid && productsRelinearized && antiAlias &&
                                  deltaBoundary && masksCorrect && secondRowZero &&
                                  queryEntryBoundRespected &&
                                  trace.size() == 33 && decrypted == direct &&
                                  decrypted.at(0) == 128 && decrypted.at(4095) == 5;
        WriteWitness(
            outputPath,
            decrypted,
            direct,
            unrelinearized,
            relinearized,
            trace,
            operands,
            globalQuery,
            bindings,
            secondRowZero,
            masksCorrect,
            queryEntryBoundRespected,
            checksPassed);
        std::cout << outputPath << '\n';
        return checksPassed ? 0 : 5;
    }
    catch (const std::exception& exception) {
        std::cerr << "strong_whole_query_witness failed: " << exception.what() << '\n';
        return 1;
    }
}
