#include "openfhe.h"
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"
#include "utils/hashutil.h"

#include "cereal/external/rapidjson/document.h"
#include "cereal/external/rapidjson/stringbuffer.h"
#include "cereal/external/rapidjson/writer.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <unistd.h>

#include "include/args.hpp"

using namespace lbcrypto;

namespace {

namespace fs = std::filesystem;
namespace json = rapidjson;

constexpr std::uint32_t kRingDimension = 8192;
constexpr std::uint32_t kBatchSize = 8192;
constexpr std::uint32_t kSingleRowSlots = 4096;
constexpr std::uint64_t kPlaintextModulus = 65537;
constexpr std::uint32_t kMultiplicativeDepth = 2;
constexpr std::uint32_t kEstimatorEvalAddCount = 0;
constexpr std::uint32_t kEstimatorKeySwitchCount = 0;
constexpr std::uint64_t kRequestByteMaximum = 128ULL * 1024ULL * 1024ULL;
constexpr char kRequestSchema[] = "dynamic-cssc-full-openfhe-query-request-v4";
constexpr char kResultSchema[] = "dynamic-cssc-full-openfhe-query-result-v4";
constexpr char kRouteAProducerResultSchema[] =
    "dynamic-cssc-route-a-openfhe-producer-result-v1";
constexpr char kRouteAReplayResultSchema[] =
    "dynamic-cssc-route-a-openfhe-replay-result-v1";
constexpr char kRouteAPackageManifestSchema[] =
    "dynamic-cssc-route-a-native-package-manifest-v1";
constexpr char kRouteAModeArgument[] = "route-a-mode";
constexpr char kProgramSchema[] = "dynamic-cssc-cloud-program-v1";
constexpr char kBindingSchema[] = "dynamic-cssc-execution-binding-v1";
constexpr char kKeyGenerationPlanSchema[] =
    "dynamic-cssc-openfhe-key-generation-plan-v2";
constexpr char kQueryDerivedRotationPlanSchema[] =
    "dynamic-cssc-openfhe-query-derived-rotation-key-plan-v1";
constexpr char kDay2RotationPlanSchema[] =
    "dynamic-cssc-publication-rotation-key-plan-v2";
constexpr char kKeyMaterialInputBindingSchema[] =
    "dynamic-cssc-openfhe-key-material-input-binding-v2";
constexpr char kKeyGenerationSessionSchema[] =
    "dynamic-cssc-openfhe-key-generation-session-v2";
constexpr char kKeyMaterialReceiptSchema[] =
    "dynamic-cssc-openfhe-key-material-receipt-v2";
constexpr char kCombinedKeyFramingSchema[] =
    "dynamic-cssc-publication-day1b-combined-evaluation-key-framing-v1";
constexpr char kCombinedKeyMagic[] = "D1BKEY01";
constexpr char kReadyRecord[] = "D1BRDY01";
constexpr char kDoneRecord[] = "D1BDON01";
constexpr char kReadyAcknowledgement[] = "D1BGO001";
constexpr char kDoneAcknowledgement[] = "D1BGO002";
constexpr char kCompilerProfile[] = "day1b-full-query-pre-admission-depth2-0-0-v1";
constexpr char kOpenFHERepository[] = "https://github.com/openfheorg/openfhe-development.git";
constexpr char kOpenFHEVersion[] = "1.5.1";
constexpr char kOpenFHECommit[] = "1306d14f8c26bb6150d3e6ad54f28dfe1007689e";

using Allocator = json::Document::AllocatorType;
using CiphertextMap = std::unordered_map<std::string, Ciphertext<DCRTPoly>>;
using RunnerArguments = std::unordered_map<std::string, std::string>;

enum class RunnerMode {
    Legacy,
    RouteAProducer,
    RouteAReplay,
};

struct PrivateCiphertextInput {
    std::string ciphertextId;
    std::string role;
    std::string f1mKind;
    std::vector<std::int64_t> values;
};

struct SerializedReceipt {
    std::uint64_t byteCount;
    std::string category;
    std::string relativePath;
    std::string sha256;
    std::string subjectId;
};

struct DecryptedResult {
    std::string resultId;
    std::vector<std::int64_t> values;
};

struct OperationCounts {
    std::uint64_t addF1mMask = 0;
    std::uint64_t decrypt = 0;
    std::uint64_t encrypt = 0;
    std::uint64_t evalAddCiphertext = 0;
    std::uint64_t evalMultPlaintextMask = 0;
    std::uint64_t multiplyCiphertexts = 0;
    std::uint64_t evalRotate = 0;
    std::uint64_t relinearize = 0;
    std::uint64_t returnResult = 0;
};

struct LifecycleOperationCounts {
    std::uint64_t contextGeneration = 0;
    std::uint64_t keyGeneration = 0;
    std::uint64_t evalMultKeyGeneration = 0;
    std::uint64_t automorphismKeyGeneration = 0;
    std::uint64_t encrypt = 0;
    std::uint64_t cryptoContextDeserialize = 0;
    std::uint64_t secretKeyDeserialize = 0;
    std::uint64_t publicKeyDeserialize = 0;
    std::uint64_t evalMultKeyDeserialize = 0;
    std::uint64_t automorphismKeyDeserialize = 0;
    std::uint64_t inputCiphertextDeserialize = 0;
    std::uint64_t decrypt = 0;
};

struct CombinedEvaluationKeySegments {
    std::string rotationKeys;
    std::string evalMultKeys;
};

struct RouteAPackageMember {
    std::uint64_t byteCount;
    std::string relativePath;
    std::string role;
    std::string sha256;
    std::string subjectId;
    std::string bytes;
};

struct KeyGenerationPlan {
    std::vector<std::int32_t> requiredExactIndices;
    std::string rotationKeyPlanSha256;
};

struct KeyMaterialReceipt {
    std::uint64_t combinedFrameByteCount;
    std::string combinedFrameSha256;
    std::string cryptoContextParameterSha256;
    std::string cryptoContextSerializationSha256;
    std::uint64_t evalMultSegmentByteCount;
    std::string evalMultSegmentSha256;
    std::vector<std::int32_t> generatedExactIndices;
    std::string inputBindingSha256;
    std::string keyGenerationPlanSha256;
    std::string keyGenerationSessionSha256;
    std::string publicKeySha256;
    std::string requestSha256;
    std::vector<std::int32_t> requiredExactIndices;
    std::string rotationKeyPlanSha256;
    std::uint64_t rotationSegmentByteCount;
    std::string rotationSegmentSha256;
};

[[noreturn]] void Fail(const std::string& message) {
    throw std::runtime_error(message);
}

void RequireExactArgumentKeys(
    const RunnerArguments& args,
    std::initializer_list<std::string_view> expected) {
    if (args.size() != expected.size()) {
        Fail("runner arguments are missing, extra, or duplicated");
    }
    for (const auto key : expected) {
        if (!args.count(std::string(key))) {
            Fail("runner arguments are missing, extra, or duplicated");
        }
    }
}

RunnerMode SelectRunnerMode(const RunnerArguments& args) {
    const auto iterator = args.find(kRouteAModeArgument);
    if (iterator == args.end()) {
        return RunnerMode::Legacy;
    }
    const auto& value = iterator->second;
    if (value == "producer") {
        return RunnerMode::RouteAProducer;
    }
    if (value == "replay") {
        return RunnerMode::RouteAReplay;
    }
    Fail("route-a-mode must be exactly producer or replay");
}

int StrictControlDescriptor(const std::string& value, const std::string& field) {
    int descriptor = -1;
    const auto parsed = std::from_chars(
        value.data(), value.data() + value.size(), descriptor);
    if (value.empty() || parsed.ec != std::errc() ||
        parsed.ptr != value.data() + value.size() || descriptor <= STDERR_FILENO) {
        Fail(field + " must be one inherited descriptor greater than stderr");
    }
    return descriptor;
}

void WriteControlRecord(int descriptor, std::string_view value) {
    std::size_t offset = 0;
    while (offset < value.size()) {
        const auto written = ::write(
            descriptor, value.data() + offset, value.size() - offset);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            Fail("runtime control record write failed");
        }
        offset += static_cast<std::size_t>(written);
    }
}

void RequireControlAcknowledgement(int descriptor, std::string_view expected) {
    std::array<char, 8> received{};
    std::size_t offset = 0;
    while (offset < received.size()) {
        const auto count = ::read(
            descriptor, received.data() + offset, received.size() - offset);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            Fail("runtime control acknowledgement ended early");
        }
        offset += static_cast<std::size_t>(count);
    }
    if (std::string_view(received.data(), received.size()) != expected) {
        Fail("runtime control acknowledgement changed");
    }
}

void ControlPoint(
    int writeDescriptor,
    int readDescriptor,
    std::string_view record,
    std::string_view acknowledgement) {
    if (record.size() != 8 || acknowledgement.size() != 8) {
        Fail("runtime control protocol width changed");
    }
    WriteControlRecord(writeDescriptor, record);
    RequireControlAcknowledgement(readDescriptor, acknowledgement);
}

std::string ReadFile(const fs::path& path, std::uint64_t maximum) {
    const auto status = fs::symlink_status(path);
    if (fs::is_symlink(status) || !fs::is_regular_file(status)) {
        Fail("request path must be one direct regular file");
    }
    const auto size = fs::file_size(path);
    // Every caller supplies a bound no larger than 2 GiB, so passing the
    // bound also proves that the value is representable as size_t on every
    // supported runner.  Avoid a tautological uintmax_t/size_t comparison on
    // 64-bit builds, where GCC diagnoses it under -Werror.
    if (size == 0 || size > maximum) {
        Fail("request file exceeds its fixed byte bounds");
    }
    std::ifstream stream(path, std::ios::in | std::ios::binary);
    if (!stream) {
        Fail("cannot open request file");
    }
    std::string content(static_cast<std::size_t>(size), '\0');
    stream.read(content.data(), static_cast<std::streamsize>(content.size()));
    if (!stream || stream.peek() != std::char_traits<char>::eof()) {
        Fail("request file changed while reading");
    }
    return content;
}

void RequireExactKeys(
    const json::Value& value,
    std::initializer_list<std::string_view> expected,
    const std::string& field) {
    if (!value.IsObject() || value.MemberCount() != expected.size()) {
        Fail(field + " keys are not exact");
    }
    auto member = value.MemberBegin();
    for (const auto key : expected) {
        if (member == value.MemberEnd() || !member->name.IsString() ||
            std::string_view(member->name.GetString(), member->name.GetStringLength()) != key) {
            Fail(field + " keys/order are not canonical");
        }
        ++member;
    }
}

const json::Value& Member(
    const json::Value& object,
    const char* name,
    const std::string_view field) {
    if (!object.IsObject() || !object.HasMember(name)) {
        Fail(std::string(field) + " is absent");
    }
    return object[name];
}

std::string StringMember(
    const json::Value& object,
    const char* name,
    const std::string& field) {
    const auto& value = Member(object, name, field);
    if (!value.IsString()) {
        Fail(field + " must be a string");
    }
    return std::string(value.GetString(), value.GetStringLength());
}

std::uint64_t UIntMember(
    const json::Value& object,
    const char* name,
    const std::string& field) {
    const auto& value = Member(object, name, field);
    if (!value.IsUint64()) {
        Fail(field + " must be an unsigned strict integer");
    }
    return value.GetUint64();
}

std::int64_t StrictInteger(const json::Value& value, const std::string& field) {
    if (!value.IsInt64()) {
        Fail(field + " must be a signed strict integer");
    }
    return value.GetInt64();
}

void RequireString(
    const json::Value& object,
    const char* name,
    const char* expected,
    const std::string& field) {
    if (StringMember(object, name, field) != expected) {
        Fail(field + " changed");
    }
}

void RequireUInt(
    const json::Value& object,
    const char* name,
    std::uint64_t expected,
    const std::string& field) {
    if (UIntMember(object, name, field) != expected) {
        Fail(field + " changed");
    }
}

void RequireFalse(const json::Value& object, const char* name, const std::string& field) {
    const auto& value = Member(object, name, field);
    if (!value.IsBool() || value.GetBool()) {
        Fail(field + " must remain false");
    }
}

void RequireTrue(const json::Value& object, const char* name, const std::string& field) {
    const auto& value = Member(object, name, field);
    if (!value.IsBool() || !value.GetBool()) {
        Fail(field + " must remain true");
    }
}

bool PrintableIdentifier(const std::string& value) {
    return !value.empty() && value.size() <= 512 &&
           std::all_of(value.begin(), value.end(), [](const unsigned char character) {
               return character >= 0x21 && character <= 0x7e;
           });
}

bool LowerSha256(const std::string& value) {
    return value.size() == 64 &&
           std::all_of(value.begin(), value.end(), [](const unsigned char character) {
               return (character >= '0' && character <= '9') ||
                      (character >= 'a' && character <= 'f');
           });
}

std::string CanonicalJson(const json::Value& value) {
    json::StringBuffer buffer;
    json::Writer<json::StringBuffer> writer(buffer);
    if (!value.Accept(writer)) {
        Fail("JSON serialization failed");
    }
    return std::string(buffer.GetString(), buffer.GetSize());
}

std::int64_t Normalize(std::int64_t value) {
    value %= static_cast<std::int64_t>(kPlaintextModulus);
    return value < 0 ? value + static_cast<std::int64_t>(kPlaintextModulus) : value;
}

void ValidateOpenFHEProfile(const json::Value& profile) {
    RequireExactKeys(
        profile,
        {"authority_state",
         "batch_size",
         "compiler_profile",
         "eval_add_count",
         "formal_parameter_claim_allowed",
         "key_switch_count",
         "key_switch_technique",
         "multiplication_technique",
         "multiplicative_depth",
         "openfhe_commit",
         "openfhe_repository",
         "openfhe_version",
         "plaintext_modulus",
         "ring_dimension",
         "scheme",
         "security_level"},
        "openfhe profile");
    RequireString(
        profile, "authority_state", "HOLD-mixed-circuit-parameter-gate", "authority_state");
    RequireUInt(profile, "batch_size", kBatchSize, "batch_size");
    RequireString(profile, "compiler_profile", kCompilerProfile, "compiler_profile");
    RequireUInt(profile, "eval_add_count", kEstimatorEvalAddCount, "eval_add_count");
    RequireFalse(
        profile, "formal_parameter_claim_allowed", "formal_parameter_claim_allowed");
    RequireUInt(profile, "key_switch_count", kEstimatorKeySwitchCount, "key_switch_count");
    RequireString(profile, "key_switch_technique", "HYBRID", "key_switch_technique");
    RequireString(
        profile,
        "multiplication_technique",
        "HPSPOVERQLEVELED",
        "multiplication_technique");
    RequireUInt(
        profile, "multiplicative_depth", kMultiplicativeDepth, "multiplicative_depth");
    RequireString(profile, "openfhe_commit", kOpenFHECommit, "openfhe_commit");
    RequireString(
        profile, "openfhe_repository", kOpenFHERepository, "openfhe_repository");
    RequireString(profile, "openfhe_version", kOpenFHEVersion, "openfhe_version");
    RequireUInt(profile, "plaintext_modulus", kPlaintextModulus, "plaintext_modulus");
    RequireUInt(profile, "ring_dimension", kRingDimension, "ring_dimension");
    RequireString(profile, "scheme", "BFVRNS", "scheme");
    RequireString(profile, "security_level", "HEStd_128_classic", "security_level");
}

void ValidateBindings(const json::Value& bindings, const json::Value& program) {
    RequireExactKeys(
        bindings,
        {"cloud_program_sha256",
         "execution_binding",
         "execution_binding_sha256",
         "execution_kind",
         "query_preparation_sha256",
         "query_private_plan_sha256"},
        "bindings");
    const auto cloudDigest = StringMember(
        bindings, "cloud_program_sha256", "cloud_program_sha256");
    const auto bindingDigest = StringMember(
        bindings, "execution_binding_sha256", "execution_binding_sha256");
    const auto privateDigest = StringMember(
        bindings, "query_private_plan_sha256", "query_private_plan_sha256");
    const auto preparationDigest = StringMember(
        bindings,
        "query_preparation_sha256",
        "query_preparation_sha256");
    const auto executionKind = StringMember(
        bindings, "execution_kind", "execution_kind");
    if (!LowerSha256(cloudDigest) || !LowerSha256(bindingDigest) ||
        !LowerSha256(privateDigest) || !LowerSha256(preparationDigest)) {
        Fail("binding digests must be lowercase SHA-256 values");
    }
    if (executionKind != "ordinary" && executionKind != "strong") {
        Fail("execution kind changed");
    }
    if (HashUtil::HashString(CanonicalJson(program)) != cloudDigest) {
        Fail("cloud program digest differs from the canonical program");
    }
    const auto& execution = Member(bindings, "execution_binding", "execution_binding");
    RequireExactKeys(
        execution,
        {"cloud_program_digest", "format", "output_plan_digest", "version_id"},
        "execution binding");
    if (StringMember(execution, "cloud_program_digest", "cloud_program_digest") != cloudDigest ||
        StringMember(execution, "format", "execution binding format") != kBindingSchema ||
        !LowerSha256(StringMember(execution, "output_plan_digest", "output_plan_digest")) ||
        !PrintableIdentifier(StringMember(execution, "version_id", "version_id")) ||
        HashUtil::HashString(CanonicalJson(execution)) != bindingDigest) {
        Fail("execution binding is not exact");
    }
}

std::vector<PrivateCiphertextInput> ParsePrivateInputs(
    const json::Value& values,
    std::uint32_t slotCount) {
    if (!values.IsArray() || values.Empty()) {
        Fail("ciphertext_values must be a nonempty array");
    }
    std::vector<PrivateCiphertextInput> parsed;
    parsed.reserve(values.Size());
    std::string previousId;
    for (const auto& value : values.GetArray()) {
        RequireExactKeys(
            value,
            {"ciphertext_id", "f1m_kind", "role", "values"},
            "ciphertext value");
        PrivateCiphertextInput input;
        input.ciphertextId = StringMember(value, "ciphertext_id", "ciphertext_id");
        input.role = StringMember(value, "role", "ciphertext role");
        if (!PrintableIdentifier(input.ciphertextId) ||
            (!previousId.empty() && input.ciphertextId <= previousId)) {
            Fail("ciphertext input identifiers are not canonical and unique");
        }
        previousId = input.ciphertextId;
        const auto& kind = Member(value, "f1m_kind", "f1m_kind");
        if (input.role == "f1m-mask") {
            if (!kind.IsString()) {
                Fail("F1-M ciphertext lacks its private kind");
            }
            input.f1mKind = std::string(kind.GetString(), kind.GetStringLength());
            if (input.f1mKind != "random-zero-sum" &&
                input.f1mKind != "encrypted-zero-dummy") {
                Fail("F1-M private kind changed");
            }
        }
        else {
            if ((input.role != "query" && input.role != "value") || !kind.IsNull()) {
                Fail("non-F1-M ciphertext role/kind changed");
            }
        }
        const auto& vector = Member(value, "values", "ciphertext values");
        if (!vector.IsArray() || vector.Size() != slotCount) {
            Fail("ciphertext vector length changed");
        }
        input.values.assign(kBatchSize, 0);
        for (json::SizeType index = 0; index < vector.Size(); ++index) {
            input.values.at(index) = Normalize(
                StrictInteger(vector[index], "ciphertext vector entry"));
        }
        parsed.push_back(std::move(input));
    }
    return parsed;
}

std::map<std::int64_t, std::int64_t> ParseRotationCatalog(
    const json::Value& catalog,
    std::uint32_t slotCount) {
    if (!catalog.IsArray()) {
        Fail("rotation_catalog must be an array");
    }
    std::map<std::int64_t, std::int64_t> rotations;
    std::int64_t previousLogical = std::numeric_limits<std::int64_t>::min();
    for (const auto& entry : catalog.GetArray()) {
        RequireExactKeys(
            entry, {"logical_shift", "openfhe_index"}, "rotation catalog entry");
        const auto logical = StrictInteger(
            Member(entry, "logical_shift", "logical_shift"), "logical_shift");
        const auto openfhe = StrictInteger(
            Member(entry, "openfhe_index", "openfhe_index"), "openfhe_index");
        if (logical == 0 || openfhe == 0 || logical <= previousLogical ||
            openfhe == std::numeric_limits<std::int64_t>::min()) {
            Fail("rotation catalog is outside the single-row exact contract");
        }
        const auto openfheMagnitude = static_cast<std::uint64_t>(
            openfhe < 0 ? -openfhe : openfhe);
        if (openfheMagnitude >= slotCount) {
            Fail("rotation catalog is outside the single-row exact contract");
        }
        previousLogical = logical;
        rotations.emplace(logical, openfhe);
    }
    return rotations;
}

std::vector<std::int32_t> ParseExactRotationIndices(
    const json::Value& value,
    const std::string& field) {
    if (!value.IsArray() || value.Empty()) {
        Fail(field + " must be one nonempty array");
    }
    std::vector<std::int32_t> result;
    std::set<std::int64_t> residues;
    std::int64_t previous = std::numeric_limits<std::int64_t>::min();
    for (const auto& item : value.GetArray()) {
        const auto index = StrictInteger(item, field + " entry");
        const auto residue = ((index % 4096) + 4096) % 4096;
        if (index == 0 || index < -4095 || index > 4095 || index <= previous ||
            !residues.insert(residue).second) {
            Fail(field + " must be canonical, nonzero, in range, and modulo-distinct");
        }
        previous = index;
        result.push_back(static_cast<std::int32_t>(index));
    }
    return result;
}

KeyGenerationPlan ParseKeyGenerationPlan(
    const json::Value& value,
    const json::Value& bindings,
    const std::map<std::int64_t, std::int64_t>& programRotations) {
    RequireExactKeys(
        value,
        {"authority_state",
         "eval_mult_key_required",
         "formal_authority_granted",
         "publication_authority",
         "rotation_key_plan",
         "rotation_key_plan_sha256",
         "schema_version"},
        "key-generation plan");
    RequireString(
        value, "authority_state", "pre-admission-only", "key-generation authority state");
    RequireTrue(value, "eval_mult_key_required", "eval-mult key requirement");
    RequireFalse(value, "formal_authority_granted", "key-generation formal authority");
    RequireFalse(value, "publication_authority", "key-generation publication authority");
    RequireString(value, "schema_version", kKeyGenerationPlanSchema, "key-generation schema");
    const auto& plan = Member(value, "rotation_key_plan", "rotation key plan");
    const auto planSha256 = StringMember(
        value, "rotation_key_plan_sha256", "rotation key-plan SHA-256");
    if (!LowerSha256(planSha256) ||
        HashUtil::HashString(CanonicalJson(plan) + "\n") != planSha256) {
        Fail("rotation key-plan SHA-256 binding changed");
    }
    const auto schema = StringMember(plan, "schema_version", "rotation key-plan schema");
    std::vector<std::int32_t> required;
    if (schema == kQueryDerivedRotationPlanSchema) {
        RequireExactKeys(
            plan,
            {"coverage_kind",
             "required_exact_indices",
             "schema_version",
             "source_cloud_program_sha256"},
            "query-derived rotation key plan");
        const auto coverage = StringMember(plan, "coverage_kind", "rotation coverage kind");
        const auto sourceCloud = StringMember(
            plan, "source_cloud_program_sha256", "rotation-plan source cloud program");
        if (!LowerSha256(sourceCloud) ||
            sourceCloud != StringMember(
                               bindings, "cloud_program_sha256", "bound cloud program")) {
            Fail("query-derived rotation plan source changed");
        }
        required = ParseExactRotationIndices(
            Member(plan, "required_exact_indices", "required rotation indices"),
            "query-derived required rotation indices");
        std::vector<std::int32_t> expected;
        for (const auto& [logical, index] : programRotations) {
            static_cast<void>(logical);
            expected.push_back(static_cast<std::int32_t>(index));
        }
        std::sort(expected.begin(), expected.end());
        expected.erase(std::unique(expected.begin(), expected.end()), expected.end());
        if (expected.empty()) {
            expected.push_back(1);
            if (coverage != "minimum-nonempty-program-cover") {
                Fail("empty program rotation coverage changed");
            }
        }
        else if (coverage != "exact-program-rotation-catalog") {
            Fail("query-derived rotation coverage changed");
        }
        if (required != expected) {
            Fail("query-derived key plan differs from program rotations");
        }
    }
    else if (schema == kDay2RotationPlanSchema) {
        RequireExactKeys(
            plan,
            {"composite_decompositions",
             "day1a_authority_receipt_sha256",
             "day1a_inventory_sha256",
             "effective_slots",
             "eval_rotate_case_ids",
             "inventory_source_schema_version",
             "key_plan_kind",
             "planned_exact_indices",
             "required_exact_indices",
             "schema_version"},
            "Day 2 rotation key plan");
        const auto sourceSchema = StringMember(
            plan, "inventory_source_schema_version", "rotation inventory source schema");
        const auto day1aAuthority = StringMember(
            plan, "day1a_authority_receipt_sha256", "Day1A authority receipt");
        const auto day1aInventory = StringMember(
            plan, "day1a_inventory_sha256", "Day1A rotation inventory");
        if (sourceSchema.empty() || !LowerSha256(day1aAuthority) ||
            !LowerSha256(day1aInventory)) {
            Fail("Day 2 rotation-plan source binding changed");
        }
        RequireUInt(plan, "effective_slots", kSingleRowSlots, "rotation effective slots");
        RequireString(
            plan, "key_plan_kind", "direct-exact-index-v1", "rotation key-plan kind");
        const auto& decompositions = Member(
            plan, "composite_decompositions", "rotation composite decompositions");
        if (!decompositions.IsArray() || !decompositions.Empty()) {
            Fail("rotation composite decompositions are forbidden");
        }
        required = ParseExactRotationIndices(
            Member(plan, "required_exact_indices", "required rotation indices"),
            "Day 2 required rotation indices");
        const auto planned = ParseExactRotationIndices(
            Member(plan, "planned_exact_indices", "planned rotation indices"),
            "Day 2 planned rotation indices");
        if (planned != required) {
            Fail("Day 2 planned rotation inventory changed");
        }
        const auto& caseIds = Member(plan, "eval_rotate_case_ids", "EvalRotate case IDs");
        if (!caseIds.IsArray() || caseIds.Size() != required.size()) {
            Fail("EvalRotate case IDs do not exactly cover the key plan");
        }
        for (json::SizeType ordinal = 0; ordinal < caseIds.Size(); ++ordinal) {
            if (!caseIds[ordinal].IsString() ||
                std::string(caseIds[ordinal].GetString(), caseIds[ordinal].GetStringLength()) !=
                    "index=" + std::to_string(required.at(ordinal))) {
                Fail("EvalRotate case ID changed");
            }
        }
        std::set<std::int32_t> requiredSet(required.begin(), required.end());
        for (const auto& [logical, index] : programRotations) {
            static_cast<void>(logical);
            if (!requiredSet.count(static_cast<std::int32_t>(index))) {
                Fail("Day 2 key plan does not cover a program rotation");
            }
        }
    }
    else {
        Fail("rotation key-plan schema is unsupported");
    }
    return KeyGenerationPlan{std::move(required), planSha256};
}

std::unordered_map<std::string, Plaintext> ParsePlaintextMasks(
    const CryptoContext<DCRTPoly>& context,
    const json::Value& masks,
    std::uint32_t slotCount) {
    if (!masks.IsArray()) {
        Fail("plaintext_masks must be an array");
    }
    std::unordered_map<std::string, Plaintext> result;
    std::string previousId;
    for (const auto& mask : masks.GetArray()) {
        RequireExactKeys(
            mask, {"length", "mask_id", "role", "values"}, "plaintext mask");
        RequireUInt(mask, "length", slotCount, "plaintext mask length");
        RequireString(mask, "role", "selection", "plaintext mask role");
        const auto id = StringMember(mask, "mask_id", "mask_id");
        if (!PrintableIdentifier(id) || (!previousId.empty() && id <= previousId)) {
            Fail("plaintext mask identifiers are not canonical and unique");
        }
        previousId = id;
        const auto& values = Member(mask, "values", "plaintext mask values");
        if (!values.IsArray() || values.Size() != slotCount) {
            Fail("plaintext mask vector length changed");
        }
        std::vector<std::int64_t> padded(kBatchSize, 0);
        for (json::SizeType index = 0; index < values.Size(); ++index) {
            const auto member = StrictInteger(values[index], "plaintext mask entry");
            if (member != 0 && member != 1) {
                Fail("selection mask entries must be strict zero or one");
            }
            padded.at(index) = member;
        }
        result.emplace(id, context->MakePackedPlaintext(padded));
    }
    return result;
}

void ValidateProgramInputs(
    const json::Value& declared,
    const std::vector<PrivateCiphertextInput>& privateInputs,
    std::uint32_t slotCount) {
    if (!declared.IsArray() || declared.Size() != privateInputs.size()) {
        Fail("declared ciphertext inputs differ from private inputs");
    }
    for (json::SizeType index = 0; index < declared.Size(); ++index) {
        const auto& value = declared[index];
        RequireExactKeys(
            value, {"ciphertext_id", "length", "role"}, "declared ciphertext input");
        RequireUInt(value, "length", slotCount, "declared ciphertext length");
        if (StringMember(value, "ciphertext_id", "declared ciphertext_id") !=
                privateInputs.at(index).ciphertextId ||
            StringMember(value, "role", "declared ciphertext role") !=
                privateInputs.at(index).role) {
            Fail("declared ciphertext identity/role differs from private input");
        }
    }
}

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
    if (!cryptoParameters ||
        cryptoParameters->GetEvalAddCount() != kEstimatorEvalAddCount ||
        cryptoParameters->GetKeySwitchCount() != kEstimatorKeySwitchCount) {
        Fail("generated OpenFHE context changed the provisional 2/0/0 profile");
    }
    context->Enable(PKE);
    context->Enable(KEYSWITCH);
    context->Enable(LEVELEDSHE);
    context->Enable(ADVANCEDSHE);
    return context;
}

template <typename Value>
std::string SerializeOpenFHE(const Value& value, const std::string& field) {
    std::stringstream stream;
    Serial::Serialize(value, stream, SerType::BINARY);
    const auto content = stream.str();
    if (content.empty()) {
        Fail(field + " OpenFHE serialization is empty");
    }
    return content;
}

void AppendUint64BigEndian(std::string& output, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        output.push_back(static_cast<char>((value >> shift) & 0xff));
    }
}

std::string DigestBytes(const std::string& digest) {
    if (!LowerSha256(digest)) {
        Fail("OpenFHE serialized segment digest is not lowercase SHA-256");
    }
    std::string result;
    result.reserve(32);
    const auto nibble = [](const char value) -> unsigned char {
        if (value >= '0' && value <= '9') {
            return static_cast<unsigned char>(value - '0');
        }
        return static_cast<unsigned char>(value - 'a' + 10);
    };
    for (std::size_t index = 0; index < digest.size(); index += 2) {
        result.push_back(static_cast<char>((nibble(digest[index]) << 4) |
                                           nibble(digest[index + 1])));
    }
    return result;
}

std::string SerializeEvalMultKeys(const CryptoContext<DCRTPoly>& context) {
    std::stringstream stream;
    if (!context->SerializeEvalMultKey(stream, SerType::BINARY)) {
        Fail("OpenFHE multiplication-key serialization failed");
    }
    const auto content = stream.str();
    if (content.empty()) {
        Fail("OpenFHE multiplication-key serialization is empty");
    }
    return content;
}

std::string SerializeRotationKeyInventory(const CryptoContext<DCRTPoly>& context) {
    std::stringstream stream;
    if (!context->SerializeEvalAutomorphismKey(stream, SerType::BINARY)) {
        Fail("OpenFHE rotation-key serialization failed");
    }
    const auto content = stream.str();
    if (content.empty()) {
        Fail("OpenFHE rotation-key serialization is empty");
    }
    return content;
}

std::string BuildCombinedEvaluationKeyFrame(
    const std::string& rotationKeys,
    const std::string& evalMultKeys) {
    if (rotationKeys.empty() || evalMultKeys.empty()) {
        Fail("combined evaluation-key segments must be nonempty");
    }
    std::string frame(kCombinedKeyMagic, 8);
    AppendUint64BigEndian(frame, static_cast<std::uint64_t>(rotationKeys.size()));
    frame.append(DigestBytes(HashUtil::HashString(rotationKeys)));
    AppendUint64BigEndian(frame, static_cast<std::uint64_t>(evalMultKeys.size()));
    frame.append(DigestBytes(HashUtil::HashString(evalMultKeys)));
    frame.append(rotationKeys);
    frame.append(evalMultKeys);
    if (frame.size() != 88 + rotationKeys.size() + evalMultKeys.size()) {
        Fail("combined evaluation-key frame length changed");
    }
    return frame;
}

std::uint64_t ReadUint64BigEndian(const std::string& content, std::size_t offset) {
    if (offset > content.size() || content.size() - offset < 8) {
        Fail("combined evaluation-key frame ended inside a length field");
    }
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < 8; ++index) {
        value = (value << 8) |
                static_cast<unsigned char>(content.at(offset + index));
    }
    return value;
}

CombinedEvaluationKeySegments ParseCombinedEvaluationKeyFrame(
    const std::string& frame) {
    if (frame.size() < 88 || frame.compare(0, 8, kCombinedKeyMagic) != 0) {
        Fail("combined evaluation-key frame magic or minimum size changed");
    }
    const auto rotationSize = ReadUint64BigEndian(frame, 8);
    const auto evalMultSize = ReadUint64BigEndian(frame, 48);
    // A segment that fits within this already-materialized string is
    // necessarily representable as size_t.  The frame-size checks therefore
    // subsume explicit size_t-maximum comparisons without target-width
    // warnings.
    if (rotationSize == 0 || evalMultSize == 0 ||
        rotationSize > frame.size() - 88 ||
        evalMultSize != frame.size() - 88 - rotationSize) {
        Fail("combined evaluation-key frame segment lengths changed");
    }
    const auto rotation = frame.substr(88, static_cast<std::size_t>(rotationSize));
    const auto evalMult = frame.substr(
        88 + static_cast<std::size_t>(rotationSize),
        static_cast<std::size_t>(evalMultSize));
    if (frame.substr(16, 32) != DigestBytes(HashUtil::HashString(rotation)) ||
        frame.substr(56, 32) != DigestBytes(HashUtil::HashString(evalMult))) {
        Fail("combined evaluation-key frame segment digest changed");
    }
    return CombinedEvaluationKeySegments{rotation, evalMult};
}

template <typename Value>
Value DeserializeOpenFHE(const std::string& content, const std::string& field) {
    std::stringstream stream(content);
    Value value;
    try {
        Serial::Deserialize(value, stream, SerType::BINARY);
    }
    catch (const std::exception&) {
        Fail(field + " OpenFHE deserialization failed");
    }
    if (!value) {
        Fail(field + " OpenFHE deserialization failed");
    }
    return value;
}

void DeserializeEvalMultKey(
    const CryptoContext<DCRTPoly>& context,
    const std::string& content) {
    std::stringstream stream(content);
    if (!context->DeserializeEvalMultKey(stream, SerType::BINARY)) {
        Fail("OpenFHE multiplication-key deserialization failed");
    }
}

void DeserializeEvalAutomorphismKey(
    const CryptoContext<DCRTPoly>& context,
    const std::string& content) {
    std::stringstream stream(content);
    if (!context->DeserializeEvalAutomorphismKey(stream, SerType::BINARY)) {
        Fail("OpenFHE automorphism-key deserialization failed");
    }
}

void WriteNewFile(const fs::path& path, const std::string& content) {
    if (fs::exists(fs::symlink_status(path))) {
        Fail("refusing to replace an existing output path");
    }
    std::ofstream stream(path, std::ios::out | std::ios::binary);
    if (!stream) {
        Fail("cannot create output file");
    }
    stream.write(content.data(), static_cast<std::streamsize>(content.size()));
    stream.flush();
    if (!stream) {
        Fail("failed to write output file");
    }
}

SerializedReceipt WriteSerializedObject(
    const fs::path& objectRoot,
    std::size_t ordinal,
    std::string category,
    std::string subjectId,
    const std::string& content) {
    if (content.empty()) {
        Fail("serialized OpenFHE object is empty");
    }
    std::ostringstream name;
    name << "object-";
    name.width(6);
    name.fill('0');
    name << ordinal << ".bin";
    const auto relativePath = name.str();
    WriteNewFile(objectRoot / relativePath, content);
    return SerializedReceipt{
        static_cast<std::uint64_t>(content.size()),
        std::move(category),
        relativePath,
        HashUtil::HashString(content),
        std::move(subjectId),
    };
}

void RequireDirectEmptyDirectory(const fs::path& root, const std::string& field) {
    const auto status = fs::symlink_status(root);
    if (fs::is_symlink(status) || !fs::is_directory(status) ||
        fs::directory_iterator(root) != fs::directory_iterator()) {
        Fail(field + " must be an existing direct empty directory");
    }
}

std::vector<RouteAPackageMember> ReadRouteAPackage(
    const fs::path& packageRoot,
    const std::string& manifestBytes) {
    const auto rootStatus = fs::symlink_status(packageRoot);
    if (fs::is_symlink(rootStatus) || !fs::is_directory(rootStatus)) {
        Fail("Route A package-dir must be one direct directory");
    }
    json::Document manifest;
    manifest.Parse<json::kParseValidateEncodingFlag>(
        manifestBytes.data(), manifestBytes.size());
    if (manifest.HasParseError() || CanonicalJson(manifest) != manifestBytes) {
        Fail("Route A package manifest is not canonical UTF-8 JSON");
    }
    RequireExactKeys(
        manifest,
        {"build_manifest_sha256",
         "case_binding_sha256",
         "formal_authority_granted",
         "lane_binding_sha256",
         "members",
         "publication_authority",
         "schema_version"},
        "Route A package manifest");
    for (const auto field : {
             "build_manifest_sha256", "case_binding_sha256", "lane_binding_sha256"}) {
        if (!LowerSha256(StringMember(manifest, field, field))) {
            Fail(std::string(field) + " must be lowercase SHA-256");
        }
    }
    const auto caseBindingSha256 = StringMember(
        manifest, "case_binding_sha256", "case_binding_sha256");
    const auto laneBindingSha256 = StringMember(
        manifest, "lane_binding_sha256", "lane_binding_sha256");
    RequireFalse(manifest, "formal_authority_granted", "Route A package authority");
    RequireFalse(manifest, "publication_authority", "Route A package publication authority");
    RequireString(
        manifest,
        "schema_version",
        kRouteAPackageManifestSchema,
        "Route A package schema");
    const auto& members = Member(manifest, "members", "Route A package members");
    if (!members.IsArray() || members.Empty()) {
        Fail("Route A package members must be a nonempty array");
    }
    std::vector<RouteAPackageMember> parsed;
    parsed.reserve(members.Size());
    std::set<std::string> rolesAndSubjects;
    std::set<std::string> observedNames{"manifest.json"};
    for (json::SizeType index = 0; index < members.Size(); ++index) {
        const auto& member = members[index];
        RequireExactKeys(
            member,
            {"byte_count", "relative_path", "role", "sha256", "subject_id"},
            "Route A package member");
        std::ostringstream expectedName;
        expectedName << "member-";
        expectedName.width(6);
        expectedName.fill('0');
        expectedName << index << ".bin";
        RouteAPackageMember item{
            UIntMember(member, "byte_count", "Route A package member byte_count"),
            StringMember(member, "relative_path", "Route A package member path"),
            StringMember(member, "role", "Route A package member role"),
            StringMember(member, "sha256", "Route A package member SHA-256"),
            StringMember(member, "subject_id", "Route A package member subject"),
            {},
        };
        if (item.byteCount == 0 || item.relativePath != expectedName.str() ||
            !PrintableIdentifier(item.role) || !PrintableIdentifier(item.subjectId) ||
            !LowerSha256(item.sha256) ||
            !rolesAndSubjects.insert(item.role + "\n" + item.subjectId).second) {
            Fail("Route A package member identity is not canonical and unique");
        }
        item.bytes = ReadFile(packageRoot / item.relativePath, 2ULL * 1024 * 1024 * 1024);
        if (item.bytes.size() != item.byteCount ||
            HashUtil::HashString(item.bytes) != item.sha256) {
            Fail("Route A package member size or digest changed");
        }
        observedNames.insert(item.relativePath);
        parsed.push_back(std::move(item));
    }
    std::set<std::string> actualNames;
    for (const auto& entry : fs::directory_iterator(packageRoot)) {
        const auto status = entry.symlink_status();
        if (fs::is_symlink(status) || !fs::is_regular_file(status)) {
            Fail("Route A package contains a non-regular member");
        }
        actualNames.insert(entry.path().filename().string());
    }
    if (actualNames != observedNames) {
        Fail("Route A package has a missing or extra physical member");
    }
    bool caseBindingMatched = false;
    bool laneBindingMatched = false;
    for (const auto& member : parsed) {
        if (member.role == "case-binding") {
            caseBindingMatched = member.sha256 == caseBindingSha256;
        }
        else if (member.role == "lane-binding") {
            laneBindingMatched = member.sha256 == laneBindingSha256;
        }
    }
    if (!caseBindingMatched || !laneBindingMatched) {
        Fail("Route A package case or lane manifest binding changed");
    }
    return parsed;
}

const RouteAPackageMember& UniqueRouteAPackageMember(
    const std::vector<RouteAPackageMember>& members,
    std::string_view role) {
    const RouteAPackageMember* found = nullptr;
    for (const auto& member : members) {
        if (member.role == role) {
            if (found != nullptr) {
                Fail("Route A package repeats one singleton role");
            }
            found = &member;
        }
    }
    if (found == nullptr) {
        Fail("Route A package lacks one required singleton role");
    }
    return *found;
}

const RouteAPackageMember& RouteAPackageMemberBySubject(
    const std::vector<RouteAPackageMember>& members,
    std::string_view role,
    const std::string& subjectId) {
    for (const auto& member : members) {
        if (member.role == role && member.subjectId == subjectId) {
            return member;
        }
    }
    Fail("Route A package lacks one required typed member");
}

std::string InputCategory(const PrivateCiphertextInput& input) {
    if (input.role == "value") {
        return "update-publication-ciphertexts";
    }
    if (input.role == "query") {
        return "query-query-ciphertexts";
    }
    return input.f1mKind == "random-zero-sum"
               ? "query-f1m-random-mask-ciphertexts"
               : "query-f1m-encrypted-zero-dummy-ciphertexts";
}

Ciphertext<DCRTPoly> ExistingCiphertext(
    const CiphertextMap& values,
    const std::string& id,
    const std::string& field) {
    const auto iterator = values.find(id);
    if (iterator == values.end()) {
        Fail(field + " does not reference a prior ciphertext");
    }
    return iterator->second;
}

void DefineCiphertext(
    CiphertextMap& values,
    std::set<std::string>& identifiers,
    const std::string& id,
    Ciphertext<DCRTPoly> ciphertext) {
    if (!PrintableIdentifier(id) || !ciphertext || !identifiers.insert(id).second ||
        !values.emplace(id, std::move(ciphertext)).second) {
        Fail("SSA result identifier/ciphertext is not exact");
    }
}

void ValidateNodeKeys(const json::Value& node, const std::string& operation) {
    if (operation == "multiply-ciphertexts" || operation == "add-ciphertexts") {
        RequireExactKeys(node, {"left_id", "op", "result_id", "right_id"}, operation);
    }
    else if (operation == "relinearize" || operation == "return-result") {
        RequireExactKeys(node, {"ciphertext_id", "op", "result_id"}, operation);
    }
    else if (operation == "rotate") {
        RequireExactKeys(
            node,
            {"ciphertext_id", "logical_shift", "op", "openfhe_index", "result_id"},
            operation);
    }
    else if (operation == "multiply-plaintext-mask") {
        RequireExactKeys(
            node, {"ciphertext_id", "mask_id", "op", "result_id"}, operation);
    }
    else if (operation == "add-f1m-mask") {
        RequireExactKeys(
            node,
            {"ciphertext_id", "mask_ciphertext_id", "mask_role", "op", "result_id"},
            operation);
    }
    else {
        Fail("typed query contains an unsupported operation");
    }
}

std::vector<std::string> ExecuteProgram(
    const CryptoContext<DCRTPoly>& context,
    const json::Value& nodes,
    const std::map<std::int64_t, std::int64_t>& rotations,
    const std::unordered_map<std::string, Plaintext>& masks,
    CiphertextMap& ciphertexts,
    std::set<std::string>& identifiers,
    OperationCounts& counts) {
    if (!nodes.IsArray() || nodes.Empty()) {
        Fail("program nodes must be a nonempty array");
    }
    std::vector<std::string> returned;
    for (const auto& node : nodes.GetArray()) {
        const auto operation = StringMember(node, "op", "node operation");
        ValidateNodeKeys(node, operation);
        const auto resultId = StringMember(node, "result_id", "node result_id");
        if (operation == "multiply-ciphertexts") {
            const auto left = ExistingCiphertext(
                ciphertexts, StringMember(node, "left_id", "left_id"), "left_id");
            const auto right = ExistingCiphertext(
                ciphertexts, StringMember(node, "right_id", "right_id"), "right_id");
            auto product = context->EvalMultNoRelin(left, right);
            if (!product || product->GetElements().size() <= 2) {
                Fail("OpenFHE multiplication did not produce an unrelinearized ciphertext");
            }
            DefineCiphertext(ciphertexts, identifiers, resultId, std::move(product));
            ++counts.multiplyCiphertexts;
        }
        else if (operation == "relinearize") {
            const auto source = ExistingCiphertext(
                ciphertexts,
                StringMember(node, "ciphertext_id", "ciphertext_id"),
                "ciphertext_id");
            if (source->GetElements().size() <= 2) {
                Fail("relinearize input is not an unrelinearized OpenFHE product");
            }
            auto relinearized = context->Relinearize(source);
            if (!relinearized || relinearized->GetElements().size() != 2) {
                Fail("OpenFHE relinearization did not produce two elements");
            }
            DefineCiphertext(ciphertexts, identifiers, resultId, std::move(relinearized));
            ++counts.relinearize;
        }
        else if (operation == "rotate") {
            const auto logical = StrictInteger(
                Member(node, "logical_shift", "logical_shift"), "logical_shift");
            const auto index = StrictInteger(
                Member(node, "openfhe_index", "openfhe_index"), "openfhe_index");
            const auto catalog = rotations.find(logical);
            if (catalog == rotations.end() || catalog->second != index ||
                index < std::numeric_limits<std::int32_t>::min() ||
                index > std::numeric_limits<std::int32_t>::max()) {
                Fail("rotation node differs from the exact catalog");
            }
            const auto source = ExistingCiphertext(
                ciphertexts,
                StringMember(node, "ciphertext_id", "ciphertext_id"),
                "ciphertext_id");
            DefineCiphertext(
                ciphertexts,
                identifiers,
                resultId,
                context->EvalRotate(source, static_cast<std::int32_t>(index)));
            ++counts.evalRotate;
        }
        else if (operation == "multiply-plaintext-mask") {
            const auto maskId = StringMember(node, "mask_id", "mask_id");
            const auto mask = masks.find(maskId);
            if (mask == masks.end()) {
                Fail("mask_id does not reference a declared plaintext mask");
            }
            const auto source = ExistingCiphertext(
                ciphertexts,
                StringMember(node, "ciphertext_id", "ciphertext_id"),
                "ciphertext_id");
            DefineCiphertext(
                ciphertexts,
                identifiers,
                resultId,
                context->EvalMult(source, mask->second));
            ++counts.evalMultPlaintextMask;
        }
        else if (operation == "add-ciphertexts") {
            const auto left = ExistingCiphertext(
                ciphertexts, StringMember(node, "left_id", "left_id"), "left_id");
            const auto right = ExistingCiphertext(
                ciphertexts, StringMember(node, "right_id", "right_id"), "right_id");
            DefineCiphertext(
                ciphertexts, identifiers, resultId, context->EvalAdd(left, right));
            ++counts.evalAddCiphertext;
        }
        else if (operation == "add-f1m-mask") {
            RequireString(node, "mask_role", "opaque-zero-sum", "mask_role");
            const auto source = ExistingCiphertext(
                ciphertexts,
                StringMember(node, "ciphertext_id", "ciphertext_id"),
                "ciphertext_id");
            const auto mask = ExistingCiphertext(
                ciphertexts,
                StringMember(node, "mask_ciphertext_id", "mask_ciphertext_id"),
                "mask_ciphertext_id");
            DefineCiphertext(
                ciphertexts, identifiers, resultId, context->EvalAdd(source, mask));
            ++counts.addF1mMask;
        }
        else {
            const auto source = ExistingCiphertext(
                ciphertexts,
                StringMember(node, "ciphertext_id", "ciphertext_id"),
                "ciphertext_id");
            DefineCiphertext(ciphertexts, identifiers, resultId, source);
            returned.push_back(resultId);
            ++counts.returnResult;
        }
    }
    return returned;
}

std::vector<std::string> ParseResultIds(const json::Value& values) {
    if (!values.IsArray() || values.Empty()) {
        Fail("result_ids must be a nonempty array");
    }
    std::vector<std::string> result;
    result.reserve(values.Size());
    for (const auto& value : values.GetArray()) {
        if (!value.IsString()) {
            Fail("result_id must be a string");
        }
        const std::string id(value.GetString(), value.GetStringLength());
        if (!PrintableIdentifier(id)) {
            Fail("result_id is not a printable identifier");
        }
        result.push_back(id);
    }
    return result;
}

void AddString(
    json::Value& object,
    const char* key,
    const std::string& value,
    Allocator& allocator) {
    json::Value name(key, allocator);
    json::Value member(value.data(), static_cast<json::SizeType>(value.size()), allocator);
    object.AddMember(name.Move(), member.Move(), allocator);
}

void AddUInt(
    json::Value& object,
    const char* key,
    std::uint64_t value,
    Allocator& allocator) {
    json::Value name(key, allocator);
    object.AddMember(name.Move(), value, allocator);
}

void AddExactIndices(
    json::Value& object,
    const char* key,
    const std::vector<std::int32_t>& indices,
    Allocator& allocator) {
    json::Value name(key, allocator);
    json::Value values(json::kArrayType);
    for (const auto index : indices) {
        values.PushBack(index, allocator);
    }
    object.AddMember(name.Move(), values.Move(), allocator);
}

std::string BuildInputBindingSha256(
    const json::Document& request,
    const std::string& keyGenerationPlanSha256) {
    json::Document binding;
    binding.SetObject();
    auto& allocator = binding.GetAllocator();
    json::Value bindings(Member(request, "bindings", "bindings"), allocator);
    binding.AddMember("bindings", bindings.Move(), allocator);
    AddString(
        binding,
        "key_generation_plan_sha256",
        keyGenerationPlanSha256,
        allocator);
    AddString(
        binding,
        "schema_version",
        kKeyMaterialInputBindingSchema,
        allocator);
    return HashUtil::HashString(CanonicalJson(binding));
}

KeyMaterialReceipt BuildKeyMaterialReceipt(
    const json::Document& request,
    const std::string& requestSha256,
    const KeyGenerationPlan& plan,
    const std::string& cryptoContextBytes,
    const std::string& publicKeyBytes,
    const std::string& rotationKeys,
    const std::string& evalMultKeys,
    const std::string& combinedFrame) {
    const auto keyGenerationPlanSha256 = HashUtil::HashString(
        CanonicalJson(Member(request, "key_generation_plan", "key-generation plan")));
    const auto inputBindingSha256 = BuildInputBindingSha256(
        request, keyGenerationPlanSha256);
    const auto contextParameterSha256 = HashUtil::HashString(
        CanonicalJson(Member(request, "openfhe", "openfhe")));
    const auto contextSerializationSha256 = HashUtil::HashString(cryptoContextBytes);
    const auto publicKeySha256 = HashUtil::HashString(publicKeyBytes);
    const auto rotationSha256 = HashUtil::HashString(rotationKeys);
    const auto evalMultSha256 = HashUtil::HashString(evalMultKeys);

    json::Document session;
    session.SetObject();
    auto& allocator = session.GetAllocator();
    AddString(
        session,
        "crypto_context_parameter_sha256",
        contextParameterSha256,
        allocator);
    AddString(
        session,
        "crypto_context_serialization_sha256",
        contextSerializationSha256,
        allocator);
    AddUInt(
        session,
        "eval_mult_segment_byte_count",
        static_cast<std::uint64_t>(evalMultKeys.size()),
        allocator);
    AddString(session, "eval_mult_segment_sha256", evalMultSha256, allocator);
    AddString(session, "input_binding_sha256", inputBindingSha256, allocator);
    AddString(
        session,
        "key_generation_plan_sha256",
        keyGenerationPlanSha256,
        allocator);
    AddString(session, "public_key_sha256", publicKeySha256, allocator);
    AddString(session, "request_sha256", requestSha256, allocator);
    AddExactIndices(
        session, "required_exact_indices", plan.requiredExactIndices, allocator);
    AddString(
        session,
        "rotation_key_plan_sha256",
        plan.rotationKeyPlanSha256,
        allocator);
    AddUInt(
        session,
        "rotation_segment_byte_count",
        static_cast<std::uint64_t>(rotationKeys.size()),
        allocator);
    AddString(session, "rotation_segment_sha256", rotationSha256, allocator);
    AddString(session, "schema_version", kKeyGenerationSessionSchema, allocator);
    const auto sessionSha256 = HashUtil::HashString(CanonicalJson(session));
    return KeyMaterialReceipt{
        static_cast<std::uint64_t>(combinedFrame.size()),
        HashUtil::HashString(combinedFrame),
        contextParameterSha256,
        contextSerializationSha256,
        static_cast<std::uint64_t>(evalMultKeys.size()),
        evalMultSha256,
        plan.requiredExactIndices,
        inputBindingSha256,
        keyGenerationPlanSha256,
        sessionSha256,
        publicKeySha256,
        requestSha256,
        plan.requiredExactIndices,
        plan.rotationKeyPlanSha256,
        static_cast<std::uint64_t>(rotationKeys.size()),
        rotationSha256,
    };
}

json::Value BuildCloudProgramOperationInventory(
    const OperationCounts& counts,
    Allocator& allocator) {
    json::Value inventory(json::kObjectType);
    AddUInt(inventory, "add_f1m_mask", counts.addF1mMask, allocator);
    AddUInt(
        inventory, "eval_add_ciphertext", counts.evalAddCiphertext, allocator);
    AddUInt(
        inventory,
        "eval_mult_plaintext_mask",
        counts.evalMultPlaintextMask,
        allocator);
    AddUInt(inventory, "eval_rotate", counts.evalRotate, allocator);
    AddUInt(
        inventory,
        "multiply_ciphertexts",
        counts.multiplyCiphertexts,
        allocator);
    AddUInt(inventory, "relinearize", counts.relinearize, allocator);
    AddUInt(inventory, "return_result", counts.returnResult, allocator);
    return inventory;
}

json::Value BuildLifecycleOperationInventory(
    const LifecycleOperationCounts& counts,
    Allocator& allocator) {
    json::Value inventory(json::kObjectType);
    AddUInt(
        inventory,
        "automorphism_key_deserialize_count",
        counts.automorphismKeyDeserialize,
        allocator);
    AddUInt(
        inventory,
        "automorphism_key_generation_count",
        counts.automorphismKeyGeneration,
        allocator);
    AddUInt(
        inventory,
        "context_generation_count",
        counts.contextGeneration,
        allocator);
    AddUInt(
        inventory,
        "crypto_context_deserialize_count",
        counts.cryptoContextDeserialize,
        allocator);
    AddUInt(inventory, "decrypt_count", counts.decrypt, allocator);
    AddUInt(inventory, "encrypt_count", counts.encrypt, allocator);
    AddUInt(
        inventory,
        "eval_mult_key_deserialize_count",
        counts.evalMultKeyDeserialize,
        allocator);
    AddUInt(
        inventory,
        "eval_mult_key_generation_count",
        counts.evalMultKeyGeneration,
        allocator);
    AddUInt(
        inventory,
        "input_ciphertext_deserialize_count",
        counts.inputCiphertextDeserialize,
        allocator);
    AddUInt(inventory, "key_generation_count", counts.keyGeneration, allocator);
    AddUInt(
        inventory,
        "public_key_deserialize_count",
        counts.publicKeyDeserialize,
        allocator);
    AddUInt(
        inventory,
        "secret_key_deserialize_count",
        counts.secretKeyDeserialize,
        allocator);
    return inventory;
}

std::string BuildResult(
    const json::Document& request,
    const std::string& requestSha256,
    const std::vector<DecryptedResult>& decrypted,
    const OperationCounts& counts,
    const LifecycleOperationCounts& lifecycleCounts,
    const KeyMaterialReceipt& keyMaterialReceipt,
    const std::vector<SerializedReceipt>& receipts,
    bool secondBatchRowZero,
    bool routeAProducer) {
    json::Document result;
    result.SetObject();
    auto& allocator = result.GetAllocator();
    json::Value bindings(Member(request, "bindings", "bindings"), allocator);
    result.AddMember("bindings", bindings.Move(), allocator);
    if (routeAProducer) {
        auto cloudInventory = BuildCloudProgramOperationInventory(counts, allocator);
        result.AddMember(
            "cloud_program_operation_inventory", cloudInventory.Move(), allocator);
    }

    json::Value decryptedValues(json::kArrayType);
    for (const auto& item : decrypted) {
        json::Value row(json::kObjectType);
        AddString(row, "result_id", item.resultId, allocator);
        json::Value values(json::kArrayType);
        for (const auto value : item.values) {
            values.PushBack(value, allocator);
        }
        row.AddMember("values", values.Move(), allocator);
        decryptedValues.PushBack(row.Move(), allocator);
    }
    result.AddMember("decrypted_results", decryptedValues.Move(), allocator);

    json::Value keyGenerationPlan(
        Member(request, "key_generation_plan", "key-generation plan"), allocator);
    result.AddMember("key_generation_plan", keyGenerationPlan.Move(), allocator);
    json::Value keyReceipt(json::kObjectType);
    AddUInt(
        keyReceipt,
        "combined_frame_byte_count",
        keyMaterialReceipt.combinedFrameByteCount,
        allocator);
    AddString(
        keyReceipt,
        "combined_frame_sha256",
        keyMaterialReceipt.combinedFrameSha256,
        allocator);
    AddString(
        keyReceipt,
        "crypto_context_parameter_sha256",
        keyMaterialReceipt.cryptoContextParameterSha256,
        allocator);
    AddString(
        keyReceipt,
        "crypto_context_serialization_sha256",
        keyMaterialReceipt.cryptoContextSerializationSha256,
        allocator);
    AddUInt(
        keyReceipt,
        "eval_mult_segment_byte_count",
        keyMaterialReceipt.evalMultSegmentByteCount,
        allocator);
    AddString(
        keyReceipt,
        "eval_mult_segment_sha256",
        keyMaterialReceipt.evalMultSegmentSha256,
        allocator);
    keyReceipt.AddMember("formal_authority_granted", false, allocator);
    AddString(keyReceipt, "framing_schema", kCombinedKeyFramingSchema, allocator);
    AddExactIndices(
        keyReceipt,
        "generated_exact_indices",
        keyMaterialReceipt.generatedExactIndices,
        allocator);
    AddString(
        keyReceipt,
        "input_binding_sha256",
        keyMaterialReceipt.inputBindingSha256,
        allocator);
    AddString(
        keyReceipt,
        "key_generation_plan_sha256",
        keyMaterialReceipt.keyGenerationPlanSha256,
        allocator);
    AddString(
        keyReceipt,
        "key_generation_session_sha256",
        keyMaterialReceipt.keyGenerationSessionSha256,
        allocator);
    AddString(
        keyReceipt,
        "public_key_sha256",
        keyMaterialReceipt.publicKeySha256,
        allocator);
    keyReceipt.AddMember("publication_authority", false, allocator);
    AddString(
        keyReceipt,
        "request_sha256",
        keyMaterialReceipt.requestSha256,
        allocator);
    AddExactIndices(
        keyReceipt,
        "required_exact_indices",
        keyMaterialReceipt.requiredExactIndices,
        allocator);
    AddString(
        keyReceipt,
        "rotation_key_plan_sha256",
        keyMaterialReceipt.rotationKeyPlanSha256,
        allocator);
    AddUInt(
        keyReceipt,
        "rotation_segment_byte_count",
        keyMaterialReceipt.rotationSegmentByteCount,
        allocator);
    AddString(
        keyReceipt,
        "rotation_segment_sha256",
        keyMaterialReceipt.rotationSegmentSha256,
        allocator);
    keyReceipt.AddMember("same_crypto_context_generation_session", true, allocator);
    AddString(keyReceipt, "schema_version", kKeyMaterialReceiptSchema, allocator);
    AddString(
        keyReceipt,
        "status",
        "verified-by-runner-pre-admission-only",
        allocator);
    result.AddMember("key_material_receipt", keyReceipt.Move(), allocator);

    if (routeAProducer) {
        auto lifecycleInventory = BuildLifecycleOperationInventory(
            lifecycleCounts, allocator);
        result.AddMember(
            "lifecycle_operation_inventory", lifecycleInventory.Move(), allocator);
        AddString(result, "mode", "producer", allocator);
    }

    json::Value openfhe(Member(request, "openfhe", "openfhe"), allocator);
    result.AddMember("openfhe", openfhe.Move(), allocator);
    if (!routeAProducer) {
        json::Value operationCounts(json::kObjectType);
        AddUInt(operationCounts, "add_f1m_mask", counts.addF1mMask, allocator);
        AddUInt(operationCounts, "decrypt", counts.decrypt, allocator);
        AddUInt(operationCounts, "encrypt", counts.encrypt, allocator);
        AddUInt(
            operationCounts,
            "eval_add_ciphertext",
            counts.evalAddCiphertext,
            allocator);
        AddUInt(
            operationCounts,
            "eval_mult_plaintext_mask",
            counts.evalMultPlaintextMask,
            allocator);
        AddUInt(operationCounts, "eval_rotate", counts.evalRotate, allocator);
        AddUInt(
            operationCounts,
            "multiply_ciphertexts",
            counts.multiplyCiphertexts,
            allocator);
        AddUInt(operationCounts, "relinearize", counts.relinearize, allocator);
        AddUInt(operationCounts, "return_result", counts.returnResult, allocator);
        result.AddMember("operation_counts", operationCounts.Move(), allocator);
    }
    result.AddMember("publication_authority", false, allocator);
    AddString(result, "request_sha256", requestSha256, allocator);
    AddString(
        result,
        "schema_version",
        routeAProducer ? kRouteAProducerResultSchema : kResultSchema,
        allocator);
    result.AddMember("second_batch_row_zero", secondBatchRowZero, allocator);

    json::Value serialized(json::kArrayType);
    for (const auto& receipt : receipts) {
        json::Value item(json::kObjectType);
        AddUInt(item, "byte_count", receipt.byteCount, allocator);
        AddString(item, "category", receipt.category, allocator);
        AddString(item, "relative_path", receipt.relativePath, allocator);
        AddString(item, "sha256", receipt.sha256, allocator);
        AddString(item, "subject_id", receipt.subjectId, allocator);
        serialized.PushBack(item.Move(), allocator);
    }
    result.AddMember("serialized_objects", serialized.Move(), allocator);
    AddString(result, "status", "pass", allocator);
    return CanonicalJson(result);
}

int RunRouteAProducer(
    const RunnerArguments& args,
    bool routeAProducer) {
        const auto controlWriteFd = StrictControlDescriptor(
            args.at("control-write-fd"), "control-write-fd");
        const auto controlReadFd = StrictControlDescriptor(
            args.at("control-read-fd"), "control-read-fd");
        if (controlWriteFd == controlReadFd) {
            Fail("runtime control descriptors must be distinct");
        }
        const fs::path requestPath(args.at("request"));
        const fs::path resultPath(args.at("result"));
        const fs::path objectRoot(args.at("object-dir"));
        RequireDirectEmptyDirectory(objectRoot, "object-dir");
        ControlPoint(
            controlWriteFd,
            controlReadFd,
            kReadyRecord,
            kReadyAcknowledgement);
        const auto requestBytes = ReadFile(requestPath, kRequestByteMaximum);
        json::Document request;
        request.Parse<json::kParseValidateEncodingFlag>(requestBytes.data(), requestBytes.size());
        if (request.HasParseError()) {
            Fail("request is not valid UTF-8 JSON");
        }
        RequireExactKeys(
            request,
            {"bindings",
             "ciphertext_values",
             "key_generation_plan",
             "openfhe",
             "program",
             "schema_version"},
            "request");
        RequireString(request, "schema_version", kRequestSchema, "request schema");
        if (CanonicalJson(request) != requestBytes) {
            Fail("request must be canonical compact JSON");
        }
        const auto& profile = Member(request, "openfhe", "openfhe");
        ValidateOpenFHEProfile(profile);
        const auto& program = Member(request, "program", "program");
        RequireExactKeys(
            program,
            {"ciphertext_inputs",
             "format",
             "nodes",
             "plaintext_masks",
             "result_ids",
             "rotation_catalog",
             "slot_count"},
            "program");
        RequireString(program, "format", kProgramSchema, "program format");
        const auto slotCountValue = UIntMember(program, "slot_count", "slot_count");
        if (slotCountValue == 0 || slotCountValue > kSingleRowSlots) {
            Fail("slot_count is outside the single-row OpenFHE contract");
        }
        const auto slotCount = static_cast<std::uint32_t>(slotCountValue);
        ValidateBindings(Member(request, "bindings", "bindings"), program);
        const auto privateInputs = ParsePrivateInputs(
            Member(request, "ciphertext_values", "ciphertext_values"), slotCount);
        ValidateProgramInputs(
            Member(program, "ciphertext_inputs", "ciphertext_inputs"),
            privateInputs,
            slotCount);
        const auto rotations = ParseRotationCatalog(
            Member(program, "rotation_catalog", "rotation_catalog"), slotCount);
        const auto keyPlan = ParseKeyGenerationPlan(
            Member(request, "key_generation_plan", "key-generation plan"),
            Member(request, "bindings", "bindings"),
            rotations);
        const auto& nodes = Member(program, "nodes", "nodes");
        if (!nodes.IsArray()) {
            Fail("nodes must be an array");
        }

        auto context = MakeContext();
        const auto keyPair = context->KeyGen();
        if (!keyPair.good()) {
            Fail("OpenFHE key generation failed");
        }
        context->EvalMultKeyGen(keyPair.secretKey);
        context->EvalRotateKeyGen(keyPair.secretKey, keyPlan.requiredExactIndices);
        const auto cryptoContextBytes = SerializeOpenFHE(context, "crypto context");
        const auto secretKeyBytes = routeAProducer
                                        ? SerializeOpenFHE(
                                              keyPair.secretKey,
                                              "secret key")
                                        : std::string{};
        const auto publicKeyBytes = SerializeOpenFHE(keyPair.publicKey, "public key");
        const auto rotationKeyBytes = SerializeRotationKeyInventory(context);
        const auto evalMultKeyBytes = SerializeEvalMultKeys(context);
        const auto combinedKeyFrame = BuildCombinedEvaluationKeyFrame(
            rotationKeyBytes, evalMultKeyBytes);
        const auto requestSha256 = HashUtil::HashString(requestBytes);
        const auto keyMaterialReceipt = BuildKeyMaterialReceipt(
            request,
            requestSha256,
            keyPlan,
            cryptoContextBytes,
            publicKeyBytes,
            rotationKeyBytes,
            evalMultKeyBytes,
            combinedKeyFrame);

        auto masks = ParsePlaintextMasks(
            context,
            Member(program, "plaintext_masks", "plaintext_masks"),
            slotCount);
        CiphertextMap ciphertexts;
        std::set<std::string> identifiers;
        OperationCounts counts;
        LifecycleOperationCounts lifecycleCounts;
        lifecycleCounts.contextGeneration = 1;
        lifecycleCounts.keyGeneration = 1;
        lifecycleCounts.evalMultKeyGeneration = 1;
        lifecycleCounts.automorphismKeyGeneration = 1;
        std::vector<SerializedReceipt> receipts;
        if (routeAProducer) {
            receipts.push_back(WriteSerializedObject(
                objectRoot,
                receipts.size(),
                "route-a-private-replay-crypto-context",
                "crypto-context",
                cryptoContextBytes));
            receipts.push_back(WriteSerializedObject(
                objectRoot,
                receipts.size(),
                "route-a-private-replay-secret-key",
                "secret-key",
                secretKeyBytes));
            receipts.push_back(WriteSerializedObject(
                objectRoot,
                receipts.size(),
                "one-time-evaluation-key-material",
                "public-key",
                publicKeyBytes));
        }
        receipts.push_back(WriteSerializedObject(
            objectRoot,
            receipts.size(),
            "one-time-evaluation-key-material",
            "evaluation-key-material",
            combinedKeyFrame));
        for (const auto& input : privateInputs) {
            const auto plaintext = context->MakePackedPlaintext(input.values);
            const auto ciphertext = context->Encrypt(keyPair.publicKey, plaintext);
            if (!ciphertext || !identifiers.insert(input.ciphertextId).second ||
                !ciphertexts.emplace(input.ciphertextId, ciphertext).second) {
                Fail("OpenFHE input encryption/identity failed");
            }
            ++counts.encrypt;
            ++lifecycleCounts.encrypt;
            receipts.push_back(WriteSerializedObject(
                objectRoot,
                receipts.size(),
                InputCategory(input),
                input.ciphertextId,
                SerializeOpenFHE(ciphertext, "input ciphertext")));
        }

        const auto returned = ExecuteProgram(
            context,
            nodes,
            rotations,
            masks,
            ciphertexts,
            identifiers,
            counts);
        const auto expectedResults = ParseResultIds(
            Member(program, "result_ids", "result_ids"));
        if (returned != expectedResults) {
            Fail("ReturnResult order differs from result_ids");
        }

        bool secondBatchRowZero = true;
        std::vector<DecryptedResult> decrypted;
        decrypted.reserve(expectedResults.size());
        for (const auto& resultId : expectedResults) {
            const auto ciphertext = ExistingCiphertext(ciphertexts, resultId, "result_id");
            Plaintext plaintext;
            const auto status = context->Decrypt(keyPair.secretKey, ciphertext, &plaintext);
            if (!status.isValid) {
                Fail("OpenFHE full-query result decryption is invalid");
            }
            ++counts.decrypt;
            ++lifecycleCounts.decrypt;
            plaintext->SetLength(kBatchSize);
            const auto lanes = plaintext->GetPackedValue();
            if (lanes.size() != kBatchSize) {
                Fail("OpenFHE decrypted packed result has the wrong batch size");
            }
            DecryptedResult item{resultId, {}};
            item.values.reserve(slotCount);
            for (std::uint32_t lane = 0; lane < kBatchSize; ++lane) {
                const auto value = Normalize(lanes.at(lane));
                if (lane < slotCount) {
                    item.values.push_back(value);
                }
                else if (value != 0) {
                    secondBatchRowZero = false;
                }
            }
            decrypted.push_back(std::move(item));
            receipts.push_back(WriteSerializedObject(
                objectRoot,
                receipts.size(),
                "query-result-ciphertexts",
                resultId,
                SerializeOpenFHE(ciphertext, "result ciphertext")));
        }
        if (!secondBatchRowZero) {
            Fail("OpenFHE full-query result escaped the effective single row");
        }
        const auto resultBytes = BuildResult(
            request,
            requestSha256,
            decrypted,
            counts,
            lifecycleCounts,
            keyMaterialReceipt,
            receipts,
            secondBatchRowZero,
            routeAProducer);
        WriteNewFile(resultPath, resultBytes);
        ControlPoint(
            controlWriteFd,
            controlReadFd,
            kDoneRecord,
            kDoneAcknowledgement);
        std::cout << resultPath.string() << '\n';
        return 0;
}

std::string BuildRouteAReplayResult(
    const json::Document& request,
    const std::string& requestSha256,
    const std::string& packageManifestSha256,
    const std::vector<DecryptedResult>& decrypted,
    const OperationCounts& counts,
    const LifecycleOperationCounts& lifecycleCounts,
    const std::vector<SerializedReceipt>& receipts,
    bool secondBatchRowZero) {
    json::Document result;
    result.SetObject();
    auto& allocator = result.GetAllocator();
    json::Value bindings(Member(request, "bindings", "bindings"), allocator);
    result.AddMember("bindings", bindings.Move(), allocator);
    auto cloudInventory = BuildCloudProgramOperationInventory(counts, allocator);
    result.AddMember(
        "cloud_program_operation_inventory", cloudInventory.Move(), allocator);
    json::Value decryptedValues(json::kArrayType);
    for (const auto& item : decrypted) {
        json::Value row(json::kObjectType);
        AddString(row, "result_id", item.resultId, allocator);
        json::Value values(json::kArrayType);
        for (const auto value : item.values) {
            values.PushBack(value, allocator);
        }
        row.AddMember("values", values.Move(), allocator);
        decryptedValues.PushBack(row.Move(), allocator);
    }
    result.AddMember("decrypted_results", decryptedValues.Move(), allocator);
    auto lifecycleInventory = BuildLifecycleOperationInventory(
        lifecycleCounts, allocator);
    result.AddMember(
        "lifecycle_operation_inventory", lifecycleInventory.Move(), allocator);
    AddString(result, "mode", "replay", allocator);
    json::Value openfhe(Member(request, "openfhe", "openfhe"), allocator);
    result.AddMember("openfhe", openfhe.Move(), allocator);
    AddString(
        result, "package_manifest_sha256", packageManifestSha256, allocator);
    result.AddMember("publication_authority", false, allocator);
    AddString(result, "request_sha256", requestSha256, allocator);
    AddString(result, "schema_version", kRouteAReplayResultSchema, allocator);
    result.AddMember("second_batch_row_zero", secondBatchRowZero, allocator);
    json::Value serialized(json::kArrayType);
    for (const auto& receipt : receipts) {
        json::Value item(json::kObjectType);
        AddUInt(item, "byte_count", receipt.byteCount, allocator);
        AddString(item, "category", receipt.category, allocator);
        AddString(item, "relative_path", receipt.relativePath, allocator);
        AddString(item, "sha256", receipt.sha256, allocator);
        AddString(item, "subject_id", receipt.subjectId, allocator);
        serialized.PushBack(item.Move(), allocator);
    }
    result.AddMember("serialized_objects", serialized.Move(), allocator);
    AddString(result, "status", "pass", allocator);
    return CanonicalJson(result);
}

int RunLegacyProducer(const RunnerArguments& args) {
    return RunRouteAProducer(args, false);
}

int RunRouteAProducer(const RunnerArguments& args) {
    return RunRouteAProducer(args, true);
}

int RunRouteAReplay(const RunnerArguments& args) {
    const auto controlWriteFd = StrictControlDescriptor(
        args.at("control-write-fd"), "control-write-fd");
    const auto controlReadFd = StrictControlDescriptor(
        args.at("control-read-fd"), "control-read-fd");
    if (controlWriteFd == controlReadFd) {
        Fail("runtime control descriptors must be distinct");
    }
    const fs::path packageRoot(args.at("package-dir"));
    const fs::path resultPath(args.at("result"));
    const fs::path objectRoot(args.at("object-dir"));
    RequireDirectEmptyDirectory(objectRoot, "object-dir");
    ControlPoint(
        controlWriteFd,
        controlReadFd,
        kReadyRecord,
        kReadyAcknowledgement);

    const auto packageManifestBytes = ReadFile(
        packageRoot / "manifest.json", kRequestByteMaximum);
    const auto packageManifestSha256 = HashUtil::HashString(packageManifestBytes);
    const auto packageMembers = ReadRouteAPackage(
        packageRoot, packageManifestBytes);
    const std::set<std::string> singletonRoles{
        "authorization-receipt",
        "canonical-request",
        "case-binding",
        "consumed-ledger",
        "crypto-context",
        "direct-oracle",
        "evaluation-key-frame",
        "lane-binding",
        "preparation",
        "producer-result",
        "public-key",
        "secret-key",
        "structural-vector",
        "typed-oracle",
    };
    std::map<std::string, std::size_t> roleCounts;
    for (const auto& member : packageMembers) {
        if (!singletonRoles.count(member.role) && member.role != "input-ciphertext" &&
            member.role != "producer-result-ciphertext") {
            Fail("Route A package contains an unknown role");
        }
        ++roleCounts[member.role];
    }
    for (const auto& role : singletonRoles) {
        if (roleCounts[role] != 1) {
            Fail("Route A package singleton role cardinality changed");
        }
    }

    const auto& requestMember = UniqueRouteAPackageMember(
        packageMembers, "canonical-request");
    const auto& contextMember = UniqueRouteAPackageMember(
        packageMembers, "crypto-context");
    const auto& secretKeyMember = UniqueRouteAPackageMember(
        packageMembers, "secret-key");
    const auto& publicKeyMember = UniqueRouteAPackageMember(
        packageMembers, "public-key");
    const auto& evaluationKeyMember = UniqueRouteAPackageMember(
        packageMembers, "evaluation-key-frame");
    static_cast<void>(UniqueRouteAPackageMember(packageMembers, "producer-result"));

    const auto& requestBytes = requestMember.bytes;
    json::Document request;
    request.Parse<json::kParseValidateEncodingFlag>(
        requestBytes.data(), requestBytes.size());
    if (request.HasParseError()) {
        Fail("Route A package request is not valid UTF-8 JSON");
    }
    RequireExactKeys(
        request,
        {"bindings",
         "ciphertext_values",
         "key_generation_plan",
         "openfhe",
         "program",
         "schema_version"},
        "request");
    RequireString(request, "schema_version", kRequestSchema, "request schema");
    if (CanonicalJson(request) != requestBytes) {
        Fail("Route A package request must be canonical compact JSON");
    }
    const auto& profile = Member(request, "openfhe", "openfhe");
    ValidateOpenFHEProfile(profile);
    const auto& program = Member(request, "program", "program");
    RequireExactKeys(
        program,
        {"ciphertext_inputs",
         "format",
         "nodes",
         "plaintext_masks",
         "result_ids",
         "rotation_catalog",
         "slot_count"},
        "program");
    RequireString(program, "format", kProgramSchema, "program format");
    const auto slotCountValue = UIntMember(program, "slot_count", "slot_count");
    if (slotCountValue == 0 || slotCountValue > kSingleRowSlots) {
        Fail("slot_count is outside the single-row OpenFHE contract");
    }
    const auto slotCount = static_cast<std::uint32_t>(slotCountValue);
    ValidateBindings(Member(request, "bindings", "bindings"), program);
    const auto privateInputs = ParsePrivateInputs(
        Member(request, "ciphertext_values", "ciphertext_values"), slotCount);
    ValidateProgramInputs(
        Member(program, "ciphertext_inputs", "ciphertext_inputs"),
        privateInputs,
        slotCount);
    const auto rotations = ParseRotationCatalog(
        Member(program, "rotation_catalog", "rotation_catalog"), slotCount);
    static_cast<void>(ParseKeyGenerationPlan(
        Member(request, "key_generation_plan", "key-generation plan"),
        Member(request, "bindings", "bindings"),
        rotations));
    const auto& nodes = Member(program, "nodes", "nodes");
    if (!nodes.IsArray()) {
        Fail("nodes must be an array");
    }

    CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
    CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys();
    CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    auto context = DeserializeOpenFHE<CryptoContext<DCRTPoly>>(
        contextMember.bytes, "crypto context");
    auto secretKey = DeserializeOpenFHE<PrivateKey<DCRTPoly>>(
        secretKeyMember.bytes, "secret key");
    auto publicKey = DeserializeOpenFHE<PublicKey<DCRTPoly>>(
        publicKeyMember.bytes, "public key");
    if (secretKey->GetKeyTag() != publicKey->GetKeyTag()) {
        Fail("Route A retained public and secret key tags differ");
    }
    const auto evaluationKeys = ParseCombinedEvaluationKeyFrame(
        evaluationKeyMember.bytes);
    DeserializeEvalMultKey(context, evaluationKeys.evalMultKeys);
    DeserializeEvalAutomorphismKey(context, evaluationKeys.rotationKeys);

    auto masks = ParsePlaintextMasks(
        context,
        Member(program, "plaintext_masks", "plaintext_masks"),
        slotCount);
    CiphertextMap ciphertexts;
    std::set<std::string> identifiers;
    LifecycleOperationCounts lifecycleCounts;
    lifecycleCounts.cryptoContextDeserialize = 1;
    lifecycleCounts.secretKeyDeserialize = 1;
    lifecycleCounts.publicKeyDeserialize = 1;
    lifecycleCounts.evalMultKeyDeserialize = 1;
    lifecycleCounts.automorphismKeyDeserialize = 1;
    for (const auto& input : privateInputs) {
        const auto& member = RouteAPackageMemberBySubject(
            packageMembers, "input-ciphertext", input.ciphertextId);
        auto ciphertext = DeserializeOpenFHE<Ciphertext<DCRTPoly>>(
            member.bytes, "input ciphertext");
        if (ciphertext->GetKeyTag() != publicKey->GetKeyTag() ||
            !identifiers.insert(input.ciphertextId).second ||
            !ciphertexts.emplace(input.ciphertextId, ciphertext).second) {
            Fail("Route A input ciphertext identity or key tag changed");
        }
        ++lifecycleCounts.inputCiphertextDeserialize;
    }

    OperationCounts counts;
    const auto returned = ExecuteProgram(
        context,
        nodes,
        rotations,
        masks,
        ciphertexts,
        identifiers,
        counts);
    const auto expectedResults = ParseResultIds(
        Member(program, "result_ids", "result_ids"));
    if (returned != expectedResults) {
        Fail("Route A replay ReturnResult order differs from result_ids");
    }
    bool secondBatchRowZero = true;
    std::vector<DecryptedResult> decrypted;
    std::vector<SerializedReceipt> receipts;
    decrypted.reserve(expectedResults.size());
    for (const auto& resultId : expectedResults) {
        static_cast<void>(RouteAPackageMemberBySubject(
            packageMembers, "producer-result-ciphertext", resultId));
        const auto ciphertext = ExistingCiphertext(ciphertexts, resultId, "result_id");
        Plaintext plaintext;
        const auto status = context->Decrypt(secretKey, ciphertext, &plaintext);
        if (!status.isValid) {
            Fail("Route A replay result decryption is invalid");
        }
        ++counts.decrypt;
        ++lifecycleCounts.decrypt;
        plaintext->SetLength(kBatchSize);
        const auto lanes = plaintext->GetPackedValue();
        if (lanes.size() != kBatchSize) {
            Fail("Route A replay decrypted result has the wrong batch size");
        }
        DecryptedResult item{resultId, {}};
        item.values.reserve(slotCount);
        for (std::uint32_t lane = 0; lane < kBatchSize; ++lane) {
            const auto value = Normalize(lanes.at(lane));
            if (lane < slotCount) {
                item.values.push_back(value);
            }
            else if (value != 0) {
                secondBatchRowZero = false;
            }
        }
        decrypted.push_back(std::move(item));
        receipts.push_back(WriteSerializedObject(
            objectRoot,
            receipts.size(),
            "query-result-ciphertexts",
            resultId,
            SerializeOpenFHE(ciphertext, "replay result ciphertext")));
    }
    if (!secondBatchRowZero) {
        Fail("Route A replay result escaped the effective single row");
    }
    if (roleCounts["input-ciphertext"] != privateInputs.size() ||
        roleCounts["producer-result-ciphertext"] != expectedResults.size()) {
        Fail("Route A package ciphertext member cardinality changed");
    }
    const auto resultBytes = BuildRouteAReplayResult(
        request,
        HashUtil::HashString(requestBytes),
        packageManifestSha256,
        decrypted,
        counts,
        lifecycleCounts,
        receipts,
        secondBatchRowZero);
    WriteNewFile(resultPath, resultBytes);
    ControlPoint(
        controlWriteFd,
        controlReadFd,
        kDoneRecord,
        kDoneAcknowledgement);
    std::cout << resultPath.string() << '\n';
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        const auto args = dynamic_cssc::ParseArgs(argc, argv);
        const auto mode = SelectRunnerMode(args);
        if (mode == RunnerMode::Legacy) {
            RequireExactArgumentKeys(
                args,
                {"request",
                 "result",
                 "object-dir",
                 "control-write-fd",
                 "control-read-fd"});
            return RunLegacyProducer(args);
        }
        if (mode == RunnerMode::RouteAProducer) {
            RequireExactArgumentKeys(
                args,
                {"route-a-mode",
                 "request",
                 "result",
                 "object-dir",
                 "control-write-fd",
                 "control-read-fd"});
            return RunRouteAProducer(args);
        }
        if (mode == RunnerMode::RouteAReplay) {
            RequireExactArgumentKeys(
                args,
                {"route-a-mode",
                 "package-dir",
                 "result",
                 "object-dir",
                 "control-write-fd",
                 "control-read-fd"});
            static_cast<void>(args.at("package-dir"));
            return RunRouteAReplay(args);
        }
        Fail("runner mode dispatch is not closed");
    }
    catch (const std::exception& exception) {
        std::cerr << "openfhe_query_runner failed: " << exception.what() << '\n';
        return 1;
    }
}
