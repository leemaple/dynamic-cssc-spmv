#include "openfhe.h"
#include "ciphertext-ser.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <numeric>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#if defined(__linux__)
#include <sched.h>
#include <sys/random.h>
#elif defined(__APPLE__)
#include <stdlib.h>
#endif

#include "include/args.hpp"

using namespace lbcrypto;

namespace {

using Clock = std::chrono::steady_clock;

constexpr std::size_t kPrimitiveCount = 14;
constexpr std::size_t kFrozenBlockCount = 14;
constexpr std::uint64_t kOperationOrderSeed = 2026082302ULL;
constexpr const char* kOperationOrderMethod =
    "domain-separated-shake256-counter-rejection-fisher-yates-v1";
constexpr const char* kMeasurementStopRule =
    "exactly-14-whole-blocks-outcome-independent-no-optional-stopping";

using OperationOrder = std::array<std::string_view, kPrimitiveCount>;

constexpr OperationOrder kPrimitiveNames = {
    "client_merge",
    "client_reorder_element",
    "decrypt",
    "deserialize_ciphertext",
    "encode",
    "encrypt",
    "eval_add_ciphertext",
    "eval_mult_plaintext_mask",
    "eval_mult_with_relinearization",
    "eval_rotate",
    "mask_map_element",
    "mask_random_element",
    "query_vector_pack",
    "serialize_ciphertext",
};

// Known answers for the repository's SHAKE256/Fisher--Yates sampler. Keeping
// the exact permutations beside the timed probe avoids making a crypto-library
// RNG part of the measurement mechanism; Python contract tests independently
// recompute every row from the frozen seed and method.
constexpr std::array<OperationOrder, kFrozenBlockCount> kOperationOrders = {{
    {"mask_random_element", "encode", "client_merge", "deserialize_ciphertext",
     "client_reorder_element", "query_vector_pack", "eval_mult_with_relinearization",
     "eval_add_ciphertext", "mask_map_element", "eval_mult_plaintext_mask", "encrypt",
     "decrypt", "eval_rotate", "serialize_ciphertext"},
    {"deserialize_ciphertext", "eval_mult_plaintext_mask", "client_merge",
     "mask_random_element", "client_reorder_element", "eval_add_ciphertext",
     "eval_mult_with_relinearization", "serialize_ciphertext", "encrypt",
     "query_vector_pack", "mask_map_element", "encode", "eval_rotate", "decrypt"},
    {"eval_rotate", "mask_random_element", "mask_map_element", "query_vector_pack",
     "client_reorder_element", "eval_add_ciphertext", "encrypt", "decrypt", "encode",
     "eval_mult_plaintext_mask", "eval_mult_with_relinearization",
     "deserialize_ciphertext", "serialize_ciphertext", "client_merge"},
    {"eval_add_ciphertext", "encode", "deserialize_ciphertext", "query_vector_pack",
     "eval_rotate", "client_reorder_element", "serialize_ciphertext", "decrypt",
     "eval_mult_plaintext_mask", "mask_random_element", "encrypt", "client_merge",
     "eval_mult_with_relinearization", "mask_map_element"},
    {"eval_mult_with_relinearization", "client_reorder_element", "eval_add_ciphertext",
     "query_vector_pack", "client_merge", "encode", "mask_random_element",
     "serialize_ciphertext", "decrypt", "eval_rotate", "encrypt", "mask_map_element",
     "deserialize_ciphertext", "eval_mult_plaintext_mask"},
    {"eval_mult_plaintext_mask", "client_reorder_element", "client_merge",
     "mask_map_element", "eval_mult_with_relinearization", "eval_add_ciphertext",
     "query_vector_pack", "encrypt", "decrypt", "deserialize_ciphertext",
     "mask_random_element", "encode", "serialize_ciphertext", "eval_rotate"},
    {"query_vector_pack", "deserialize_ciphertext", "eval_add_ciphertext",
     "eval_mult_with_relinearization", "eval_rotate", "serialize_ciphertext", "encrypt",
     "mask_random_element", "eval_mult_plaintext_mask", "client_merge", "mask_map_element",
     "client_reorder_element", "decrypt", "encode"},
    {"client_merge", "encode", "deserialize_ciphertext", "serialize_ciphertext",
     "eval_mult_with_relinearization", "eval_rotate", "query_vector_pack",
     "client_reorder_element", "encrypt", "mask_map_element", "decrypt",
     "mask_random_element", "eval_add_ciphertext", "eval_mult_plaintext_mask"},
    {"eval_add_ciphertext", "encode", "encrypt", "deserialize_ciphertext",
     "eval_mult_plaintext_mask", "client_reorder_element", "decrypt",
     "mask_random_element", "mask_map_element", "client_merge",
     "eval_mult_with_relinearization", "query_vector_pack", "serialize_ciphertext",
     "eval_rotate"},
    {"client_merge", "eval_mult_with_relinearization", "eval_mult_plaintext_mask",
     "eval_rotate", "deserialize_ciphertext", "mask_random_element", "decrypt",
     "serialize_ciphertext", "encode", "encrypt", "eval_add_ciphertext",
     "mask_map_element", "client_reorder_element", "query_vector_pack"},
    {"serialize_ciphertext", "eval_add_ciphertext", "client_merge", "decrypt",
     "client_reorder_element", "encrypt", "deserialize_ciphertext", "eval_rotate",
     "mask_map_element", "mask_random_element", "eval_mult_plaintext_mask",
     "eval_mult_with_relinearization", "query_vector_pack", "encode"},
    {"client_merge", "eval_mult_plaintext_mask", "deserialize_ciphertext",
     "query_vector_pack", "mask_random_element", "client_reorder_element", "eval_rotate",
     "encode", "serialize_ciphertext", "decrypt", "encrypt", "eval_add_ciphertext",
     "mask_map_element", "eval_mult_with_relinearization"},
    {"client_merge", "eval_mult_with_relinearization", "encode",
     "client_reorder_element", "decrypt", "eval_add_ciphertext", "query_vector_pack",
     "encrypt", "deserialize_ciphertext", "eval_rotate", "serialize_ciphertext",
     "eval_mult_plaintext_mask", "mask_random_element", "mask_map_element"},
    {"eval_mult_with_relinearization", "mask_random_element", "decrypt",
     "eval_add_ciphertext", "mask_map_element", "query_vector_pack",
     "serialize_ciphertext", "encrypt", "client_merge", "eval_rotate", "encode",
     "deserialize_ciphertext", "eval_mult_plaintext_mask", "client_reorder_element"},
}};

struct CaseMeasurement {
    std::string caseId;
    std::uint64_t elapsedNs;
    std::size_t operationCount;
};

struct PrimitiveSample {
    std::string primitiveName;
    std::vector<CaseMeasurement> cases;
};

struct RawBlock {
    std::size_t ordinal;
    OperationOrder operationOrder;
    std::vector<PrimitiveSample> samples;
};

struct Summary {
    double medianMs;
    double p95Ms;
    std::size_t repetitions;
};

template <class Function>
std::uint64_t MeasureNs(Function&& function) {
    const auto begin = Clock::now();
    function();
    const auto end = Clock::now();
    const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin).count();
    return static_cast<std::uint64_t>(std::max<std::int64_t>(elapsed, 1));
}

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

void FillOperatingSystemRandom(void* target, std::size_t byteCount) {
#if defined(__linux__)
    auto* cursor = static_cast<unsigned char*>(target);
    while (byteCount > 0) {
        const auto received = ::getrandom(cursor, byteCount, 0);
        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received <= 0) {
            throw std::runtime_error(
                std::string("operating-system CSPRNG failed: ") + std::strerror(errno));
        }
        cursor += received;
        byteCount -= static_cast<std::size_t>(received);
    }
#elif defined(__APPLE__)
    ::arc4random_buf(target, byteCount);
#else
    (void)target;
    (void)byteCount;
    throw std::runtime_error("publication random-element timing requires an OS CSPRNG");
#endif
}

void WriteStringArray(std::ostream& output, const OperationOrder& values) {
    output << '[';
    for (std::size_t index = 0; index < values.size(); ++index) {
        if (index != 0) {
            output << ',';
        }
        output << '"' << dynamic_cssc::JsonEscape(std::string(values[index])) << '"';
    }
    output << ']';
}

void WriteIntArray(std::ostream& output, const std::vector<int32_t>& values) {
    output << '[';
    for (std::size_t index = 0; index < values.size(); ++index) {
        if (index != 0) {
            output << ',';
        }
        output << values[index];
    }
    output << ']';
}

std::vector<int32_t> ProcessAffinityCpuList() {
#if defined(__linux__)
    cpu_set_t affinity;
    CPU_ZERO(&affinity);
    if (::sched_getaffinity(0, sizeof(affinity), &affinity) != 0) {
        throw std::runtime_error(
            std::string("sched_getaffinity failed: ") + std::strerror(errno));
    }
    std::vector<int32_t> cpus;
    for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
        if (CPU_ISSET(cpu, &affinity)) {
            cpus.push_back(cpu);
        }
    }
    if (cpus.empty()) {
        throw std::runtime_error("process affinity CPU list is empty");
    }
    return cpus;
#else
    throw std::runtime_error("publication affinity capture requires Linux");
#endif
}

bool IsExactFrozenLabelRotation(
    const std::vector<int64_t>& values,
    std::size_t batchSize,
    int32_t rotationIndex) {
    if (values.size() != batchSize) {
        return false;
    }
    const auto signedBatchSize = static_cast<std::int64_t>(batchSize);
    const auto normalized =
        (static_cast<std::int64_t>(rotationIndex) % signedBatchSize + signedBatchSize) %
        signedBatchSize;
    for (std::size_t slot = 0; slot < batchSize; ++slot) {
        const auto expected = static_cast<std::int64_t>(
            (static_cast<std::int64_t>(slot) + normalized) % signedBatchSize);
        if (values[slot] != expected) {
            return false;
        }
    }
    return true;
}

class BenchmarkFixture {
  public:
    BenchmarkFixture(
        std::uint32_t ringDim,
        std::uint64_t plaintextModulus,
        std::uint32_t batchSize,
        std::uint32_t multiplicativeDepth,
        const std::vector<int32_t>& rotationIndices)
        : context_(MakeContext(ringDim, plaintextModulus, batchSize, multiplicativeDepth)),
          plaintextModulus_(plaintextModulus),
          batchSize_(batchSize),
          clientOperationCount_(std::min<std::size_t>(4096, batchSize)) {
        if (plaintextModulus <= batchSize || clientOperationCount_ == 0) {
            throw std::runtime_error(
                "plaintext modulus must exceed a nonempty batch for exact fixture labels");
        }
        keyPair_ = context_->KeyGen();
        if (!keyPair_.good()) {
            throw std::runtime_error("OpenFHE key generation failed");
        }
        context_->EvalMultKeyGen(keyPair_.secretKey);
        context_->EvalRotateKeyGen(keyPair_.secretKey, rotationIndices);

        ones_.assign(batchSize_, 1);
        mask_.assign(batchSize_, 0);
        labels_.resize(batchSize_);
        for (std::size_t index = 0; index < batchSize_; ++index) {
            mask_[index] = (index % 2 == 0) ? 1 : 0;
            labels_[index] = static_cast<int64_t>(index);
        }
        f1mRandomZeroSum_.assign(batchSize_, 0);
        f1mEncryptedZeroDummy_.assign(batchSize_, 0);
        if (batchSize_ < 2) {
            throw std::runtime_error("F1-M serialized-size fixtures require two slots");
        }
        f1mRandomZeroSum_[0] = 1;
        f1mRandomZeroSum_[1] = static_cast<int64_t>(plaintextModulus_ - 1);
        plaintext_ = context_->MakePackedPlaintext(ones_);
        maskPlaintext_ = context_->MakePackedPlaintext(mask_);
        const auto labelPlaintext = context_->MakePackedPlaintext(labels_);
        const auto f1mRandomPlaintext = context_->MakePackedPlaintext(f1mRandomZeroSum_);
        const auto f1mDummyPlaintext = context_->MakePackedPlaintext(f1mEncryptedZeroDummy_);
        ciphertext_ = context_->Encrypt(keyPair_.publicKey, plaintext_);
        ciphertext2_ = context_->Encrypt(keyPair_.publicKey, plaintext_);
        labelCiphertext_ = context_->Encrypt(keyPair_.publicKey, labelPlaintext);
        f1mRandomZeroSumCiphertext_ =
            context_->Encrypt(keyPair_.publicKey, f1mRandomPlaintext);
        f1mEncryptedZeroDummyCiphertext_ =
            context_->Encrypt(keyPair_.publicKey, f1mDummyPlaintext);

        std::stringstream ciphertextStream;
        Serial::Serialize(ciphertext_, ciphertextStream, SerType::BINARY);
        serializedCiphertext_ = ciphertextStream.str();
        std::stringstream f1mRandomStream;
        Serial::Serialize(f1mRandomZeroSumCiphertext_, f1mRandomStream, SerType::BINARY);
        serializedF1mRandomZeroSumCiphertext_ = f1mRandomStream.str();
        std::stringstream f1mDummyStream;
        Serial::Serialize(
            f1mEncryptedZeroDummyCiphertext_, f1mDummyStream, SerType::BINARY);
        serializedF1mEncryptedZeroDummyCiphertext_ = f1mDummyStream.str();
        if (serializedF1mRandomZeroSumCiphertext_.empty() ||
            serializedF1mEncryptedZeroDummyCiphertext_.empty()) {
            throw std::runtime_error("F1-M ciphertext serialization failed");
        }

        std::stringstream rotationKeyStream;
        if (!context_->SerializeEvalAutomorphismKey(rotationKeyStream, SerType::BINARY)) {
            throw std::runtime_error("rotation-key serialization failed");
        }
        serializedRotationKeys_ = rotationKeyStream.str();
        std::stringstream evalMultKeyStream;
        if (!context_->SerializeEvalMultKey(evalMultKeyStream, SerType::BINARY)) {
            throw std::runtime_error("evaluation-multiplication-key serialization failed");
        }
        serializedEvalMultKeys_ = evalMultKeyStream.str();

        clientLeft_.resize(clientOperationCount_);
        clientRight_.resize(clientOperationCount_);
        clientPermutation_.resize(clientOperationCount_);
        clientResult_.resize(clientOperationCount_);
        randomResidues_.resize(clientOperationCount_);
        for (std::size_t index = 0; index < clientOperationCount_; ++index) {
            clientLeft_[index] = static_cast<std::uint64_t>(index) % plaintextModulus_;
            clientRight_[index] = static_cast<std::uint64_t>(2 * index + 1) % plaintextModulus_;
            clientPermutation_[index] = (index * 17) % clientOperationCount_;
        }
    }

    std::size_t ciphertextBytes() const {
        return serializedCiphertext_.size();
    }

    std::size_t f1mRandomZeroSumCiphertextBytes() const {
        return serializedF1mRandomZeroSumCiphertext_.size();
    }

    std::size_t f1mEncryptedZeroDummyCiphertextBytes() const {
        return serializedF1mEncryptedZeroDummyCiphertext_.size();
    }

    std::size_t rotationKeyBytes() const {
        return serializedRotationKeys_.size();
    }

    std::size_t evalMultKeyBytes() const {
        return serializedEvalMultKeys_.size();
    }

    void writeEvaluationKeyMaterial(
        const std::string& rotationKeysOutput,
        const std::string& evalMultKeyOutput) const {
        if (rotationKeysOutput.empty() != evalMultKeyOutput.empty()) {
            throw std::runtime_error(
                "rotation and evaluation-multiplication key outputs must be supplied together");
        }
        if (rotationKeysOutput.empty()) {
            return;
        }
        const auto writeBinary = [](const std::string& path, const std::string& content) {
            std::ofstream output(path, std::ios::out | std::ios::binary | std::ios::trunc);
            if (!output) {
                throw std::runtime_error("cannot open evaluation-key output: " + path);
            }
            output.write(content.data(), static_cast<std::streamsize>(content.size()));
            output.flush();
            if (!output) {
                throw std::runtime_error("evaluation-key output write failed: " + path);
            }
        };
        writeBinary(rotationKeysOutput, serializedRotationKeys_);
        writeBinary(evalMultKeyOutput, serializedEvalMultKeys_);
    }

    PrimitiveSample measure(
        std::string_view primitiveName,
        const std::vector<int32_t>& rotationIndices) {
        PrimitiveSample sample{std::string(primitiveName), {}};
        if (primitiveName == "client_merge") {
            const auto elapsed = MeasureNs([&] {
                for (std::size_t index = 0; index < clientOperationCount_; ++index) {
                    clientResult_[index] =
                        (clientLeft_[index] + clientRight_[index]) % plaintextModulus_;
                }
            });
            for (std::size_t index = 0; index < clientOperationCount_; ++index) {
                const auto expected =
                    (clientLeft_[index] + clientRight_[index]) % plaintextModulus_;
                if (clientResult_[index] != expected) {
                    throw std::runtime_error("client_merge correctness check failed");
                }
            }
            sample.cases.push_back({"admitted-case", elapsed, clientOperationCount_});
        }
        else if (primitiveName == "client_reorder_element") {
            const auto elapsed = MeasureNs([&] {
                for (std::size_t index = 0; index < clientOperationCount_; ++index) {
                    clientResult_[index] = clientLeft_[clientOperationCount_ - 1 - index];
                }
            });
            if (clientResult_.front() != clientLeft_.back() ||
                clientResult_.back() != clientLeft_.front()) {
                throw std::runtime_error("client_reorder_element correctness check failed");
            }
            sample.cases.push_back({"admitted-case", elapsed, clientOperationCount_});
        }
        else if (primitiveName == "mask_map_element") {
            const auto elapsed = MeasureNs([&] {
                for (std::size_t index = 0; index < clientOperationCount_; ++index) {
                    clientResult_[index] = clientLeft_[clientPermutation_[index]];
                }
            });
            for (std::size_t index = 0; index < clientOperationCount_; ++index) {
                if (clientResult_[index] != clientLeft_[clientPermutation_[index]]) {
                    throw std::runtime_error("mask_map_element correctness check failed");
                }
            }
            sample.cases.push_back({"admitted-case", elapsed, clientOperationCount_});
        }
        else if (primitiveName == "mask_random_element") {
            const auto elapsed = MeasureNs([&] { fillRandomResidues(); });
            if (std::any_of(
                    randomResidues_.begin(),
                    randomResidues_.end(),
                    [&](std::uint64_t value) { return value >= plaintextModulus_; })) {
                throw std::runtime_error("mask_random_element correctness check failed");
            }
            sample.cases.push_back({"admitted-case", elapsed, clientOperationCount_});
        }
        else if (primitiveName == "query_vector_pack") {
            const auto elapsed = MeasureNs([&] {
                for (std::size_t index = 0; index < clientOperationCount_; ++index) {
                    clientResult_[index] = (index % 11 == 0) ? 1 : 0;
                }
            });
            for (std::size_t index = 0; index < clientOperationCount_; ++index) {
                if (clientResult_[index] != ((index % 11 == 0) ? 1U : 0U)) {
                    throw std::runtime_error("query_vector_pack correctness check failed");
                }
            }
            sample.cases.push_back({"admitted-case", elapsed, clientOperationCount_});
        }
        else if (primitiveName == "encode") {
            const auto elapsed = MeasureNs(
                [&] { plaintext_ = context_->MakePackedPlaintext(ones_); });
            requirePackedValues(plaintext_, ones_, "encode");
            sample.cases.push_back({"admitted-case", elapsed, 1});
        }
        else if (primitiveName == "encrypt") {
            const auto elapsed = MeasureNs(
                [&] { ciphertext_ = context_->Encrypt(keyPair_.publicKey, plaintext_); });
            requireCiphertextValues(ciphertext_, ones_, "encrypt");
            sample.cases.push_back({"admitted-case", elapsed, 1});
        }
        else if (primitiveName == "serialize_ciphertext") {
            const auto elapsed = MeasureNs([&] {
                std::stringstream stream;
                Serial::Serialize(ciphertext_, stream, SerType::BINARY);
                serializedCiphertext_ = stream.str();
            });
            if (serializedCiphertext_.empty()) {
                throw std::runtime_error("serialize_ciphertext correctness check failed");
            }
            sample.cases.push_back({"admitted-case", elapsed, 1});
        }
        else if (primitiveName == "deserialize_ciphertext") {
            const auto elapsed = MeasureNs([&] {
                std::stringstream stream(serializedCiphertext_);
                Ciphertext<DCRTPoly> restored;
                Serial::Deserialize(restored, stream, SerType::BINARY);
                sink_ = restored;
            });
            requireCiphertextValues(sink_, ones_, "deserialize_ciphertext");
            sample.cases.push_back({"admitted-case", elapsed, 1});
        }
        else if (primitiveName == "eval_mult_with_relinearization") {
            const auto elapsed = MeasureNs(
                [&] { sink_ = context_->EvalMult(ciphertext_, ciphertext2_); });
            requireCiphertextValues(sink_, ones_, "eval_mult_with_relinearization");
            sample.cases.push_back({"admitted-case", elapsed, 1});
        }
        else if (primitiveName == "eval_rotate") {
            for (const auto rotationIndex : rotationIndices) {
                const auto elapsed = MeasureNs(
                    [&] { sink_ = context_->EvalRotate(labelCiphertext_, rotationIndex); });
                Plaintext rotated;
                const auto result = context_->Decrypt(keyPair_.secretKey, sink_, &rotated);
                if (!result.isValid ||
                    !IsExactFrozenLabelRotation(
                        rotated->GetPackedValue(), batchSize_, rotationIndex)) {
                    throw std::runtime_error("eval_rotate correctness check failed");
                }
                sample.cases.push_back(
                    {"index=" + std::to_string(rotationIndex), elapsed, 1});
            }
        }
        else if (primitiveName == "eval_add_ciphertext") {
            const auto elapsed = MeasureNs(
                [&] { sink_ = context_->EvalAdd(ciphertext_, ciphertext2_); });
            std::vector<int64_t> expected(batchSize_, 2);
            requireCiphertextValues(sink_, expected, "eval_add_ciphertext");
            sample.cases.push_back({"admitted-case", elapsed, 1});
        }
        else if (primitiveName == "eval_mult_plaintext_mask") {
            const auto elapsed = MeasureNs(
                [&] { sink_ = context_->EvalMult(ciphertext_, maskPlaintext_); });
            requireCiphertextValues(sink_, mask_, "eval_mult_plaintext_mask");
            sample.cases.push_back({"admitted-case", elapsed, 1});
        }
        else if (primitiveName == "decrypt") {
            const auto elapsed = MeasureNs(
                [&] { decryptResult_ = context_->Decrypt(keyPair_.secretKey, ciphertext_, &decrypted_); });
            if (!decryptResult_.isValid) {
                throw std::runtime_error("decrypt returned an invalid result");
            }
            requirePackedValues(decrypted_, ones_, "decrypt");
            sample.cases.push_back({"admitted-case", elapsed, 1});
        }
        else {
            throw std::runtime_error("unknown publication calibration primitive");
        }
        return sample;
    }

  private:
    void fillRandomResidues() {
        const auto threshold = static_cast<std::uint64_t>(-plaintextModulus_) % plaintextModulus_;
        for (auto& output : randomResidues_) {
            std::uint64_t candidate = 0;
            do {
                FillOperatingSystemRandom(&candidate, sizeof(candidate));
            } while (candidate < threshold);
            output = candidate % plaintextModulus_;
        }
    }

    void requirePackedValues(
        const Plaintext& plaintext,
        const std::vector<int64_t>& expected,
        std::string_view operation) const {
        const auto& actual = plaintext->GetPackedValue();
        if (actual.size() != expected.size() ||
            !std::equal(actual.begin(), actual.end(), expected.begin())) {
            throw std::runtime_error(std::string(operation) + " correctness check failed");
        }
    }

    void requireCiphertextValues(
        const Ciphertext<DCRTPoly>& ciphertext,
        const std::vector<int64_t>& expected,
        std::string_view operation) const {
        Plaintext decrypted;
        const auto result = context_->Decrypt(keyPair_.secretKey, ciphertext, &decrypted);
        if (!result.isValid) {
            throw std::runtime_error(std::string(operation) + " decryption was invalid");
        }
        requirePackedValues(decrypted, expected, operation);
    }

    CryptoContext<DCRTPoly> context_;
    KeyPair<DCRTPoly> keyPair_;
    std::uint64_t plaintextModulus_;
    std::size_t batchSize_;
    std::size_t clientOperationCount_;
    std::vector<int64_t> ones_;
    std::vector<int64_t> mask_;
    std::vector<int64_t> labels_;
    std::vector<int64_t> f1mRandomZeroSum_;
    std::vector<int64_t> f1mEncryptedZeroDummy_;
    Plaintext plaintext_;
    Plaintext maskPlaintext_;
    Ciphertext<DCRTPoly> ciphertext_;
    Ciphertext<DCRTPoly> ciphertext2_;
    Ciphertext<DCRTPoly> labelCiphertext_;
    Ciphertext<DCRTPoly> f1mRandomZeroSumCiphertext_;
    Ciphertext<DCRTPoly> f1mEncryptedZeroDummyCiphertext_;
    Ciphertext<DCRTPoly> sink_;
    Plaintext decrypted_;
    DecryptResult decryptResult_;
    std::string serializedCiphertext_;
    std::string serializedF1mRandomZeroSumCiphertext_;
    std::string serializedF1mEncryptedZeroDummyCiphertext_;
    std::string serializedRotationKeys_;
    std::string serializedEvalMultKeys_;
    std::vector<std::uint64_t> clientLeft_;
    std::vector<std::uint64_t> clientRight_;
    std::vector<std::size_t> clientPermutation_;
    std::vector<std::uint64_t> clientResult_;
    std::vector<std::uint64_t> randomResidues_;
};

std::vector<RawBlock> RunBlocks(
    BenchmarkFixture& fixture,
    std::size_t count,
    const std::vector<int32_t>& rotationIndices) {
    if (count > kFrozenBlockCount) {
        throw std::runtime_error("raw calibration block count exceeds the frozen order table");
    }
    std::vector<RawBlock> blocks;
    blocks.reserve(count);
    for (std::size_t ordinal = 0; ordinal < count; ++ordinal) {
        RawBlock block{ordinal, kOperationOrders[ordinal], {}};
        block.samples.reserve(kPrimitiveCount);
        for (const auto primitiveName : block.operationOrder) {
            block.samples.push_back(fixture.measure(primitiveName, rotationIndices));
        }
        blocks.push_back(std::move(block));
    }
    return blocks;
}

void WriteBlock(std::ostream& output, const RawBlock& block, const std::string& indent) {
    output << indent << "{\"ordinal\":" << block.ordinal << ",\"operation_order\":";
    WriteStringArray(output, block.operationOrder);
    output << ",\"samples\":[";
    for (std::size_t sampleIndex = 0; sampleIndex < block.samples.size(); ++sampleIndex) {
        if (sampleIndex != 0) {
            output << ',';
        }
        const auto& sample = block.samples[sampleIndex];
        output << "{\"primitive_name\":\""
               << dynamic_cssc::JsonEscape(sample.primitiveName) << "\",\"cases\":[";
        for (std::size_t caseIndex = 0; caseIndex < sample.cases.size(); ++caseIndex) {
            if (caseIndex != 0) {
                output << ',';
            }
            const auto& measuredCase = sample.cases[caseIndex];
            output << "{\"case_id\":\"" << dynamic_cssc::JsonEscape(measuredCase.caseId)
                   << "\",\"elapsed_ns\":" << measuredCase.elapsedNs
                   << ",\"operation_count\":" << measuredCase.operationCount << '}';
        }
        output << "]}";
    }
    output << "]}";
}

void WriteBlocks(
    std::ostream& output,
    const std::vector<RawBlock>& blocks,
    const std::string& indent) {
    output << '[';
    for (std::size_t index = 0; index < blocks.size(); ++index) {
        if (index != 0) {
            output << ',';
        }
        output << '\n';
        WriteBlock(output, blocks[index], indent);
    }
    if (!blocks.empty()) {
        output << '\n' << indent.substr(0, indent.size() - 2);
    }
    output << ']';
}

std::map<std::string, Summary> Summaries(const std::vector<RawBlock>& blocks) {
    std::map<std::string, std::vector<double>> samplesByPrimitive;
    for (const auto& name : kPrimitiveNames) {
        samplesByPrimitive[std::string(name)] = {};
    }
    for (const auto& block : blocks) {
        for (const auto& sample : block.samples) {
            double worstCaseMs = 0.0;
            for (const auto& measuredCase : sample.cases) {
                const auto perOperationMs =
                    static_cast<double>(measuredCase.elapsedNs) /
                    static_cast<double>(measuredCase.operationCount) / 1'000'000.0;
                worstCaseMs = std::max(worstCaseMs, perOperationMs);
            }
            samplesByPrimitive[sample.primitiveName].push_back(worstCaseMs);
        }
    }
    std::map<std::string, Summary> summaries;
    for (auto& [name, values] : samplesByPrimitive) {
        summaries.emplace(name, Summarize(std::move(values)));
    }
    return summaries;
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
        const auto rotationKeysOutput =
            dynamic_cssc::GetString(args, "rotation-keys-output", "");
        const auto evalMultKeyOutput =
            dynamic_cssc::GetString(args, "eval-mult-key-output", "");
        const auto ringDim = dynamic_cssc::GetUInt(args, "ring-dim", 8192);
        const auto plaintextModulus = dynamic_cssc::GetUInt(args, "plaintext-modulus", 65537);
        const auto batchSize = dynamic_cssc::GetUInt(args, "batch-size", ringDim);
        const auto multiplicativeDepth = dynamic_cssc::GetUInt(args, "multiplicative-depth", 2);
        const auto noiseBudgetProfile = dynamic_cssc::GetString(
            args, "noise-budget-profile", "");
        const auto warmups = dynamic_cssc::GetUInt(args, "warmups", 3);
        const auto repetitions = dynamic_cssc::GetUInt(args, "repetitions", 11);
        auto rotationIndices = dynamic_cssc::ParseIndices(
            dynamic_cssc::GetString(args, "indices", "1,-1,2,-2,4,-4,8,-8"));

        if (noiseBudgetProfile != "day2_mult_only") {
            std::cerr << "noise-budget-profile must be day2_mult_only\n";
            return 5;
        }
        if (rotationIndices.empty() ||
            std::any_of(rotationIndices.begin(), rotationIndices.end(), [](int32_t value) {
                return value == 0;
            })) {
            std::cerr << "at least one nonzero exact rotation index is required\n";
            return 6;
        }
        const auto originalRotationCount = rotationIndices.size();
        std::sort(rotationIndices.begin(), rotationIndices.end());
        rotationIndices.erase(
            std::unique(rotationIndices.begin(), rotationIndices.end()), rotationIndices.end());
        if (rotationIndices.size() != originalRotationCount) {
            std::cerr << "rotation indices must be unique\n";
            return 6;
        }
        if (warmups > kFrozenBlockCount || repetitions > kFrozenBlockCount) {
            std::cerr << "warmup and measurement counts cannot exceed 14 whole blocks\n";
            return 6;
        }

        const auto processAffinityCpuList = ProcessAffinityCpuList();
        BenchmarkFixture fixture(
            ringDim,
            plaintextModulus,
            batchSize,
            multiplicativeDepth,
            rotationIndices);
        fixture.writeEvaluationKeyMaterial(rotationKeysOutput, evalMultKeyOutput);
        const auto warmupBlocks = RunBlocks(fixture, warmups, rotationIndices);
        const auto measurementBlocks = RunBlocks(fixture, repetitions, rotationIndices);
        const auto summaries = Summaries(measurementBlocks);
        if (ProcessAffinityCpuList() != processAffinityCpuList) {
            throw std::runtime_error("process affinity changed during calibration");
        }

        std::ofstream output(outputPath, std::ios::out | std::ios::trunc);
        if (!output) {
            std::cerr << "cannot open output: " << outputPath << '\n';
            return 4;
        }
        output << "{\n";
        output << "  \"schema_version\": \"dynamic-cssc-day2-raw-block-probe-v1\",\n";
        output << "  \"status\": \"measured-openfhe\",\n";
        output << "  \"noise_budget_profile\": \""
               << dynamic_cssc::JsonEscape(noiseBudgetProfile) << "\",\n";
        output << "  \"evidence_scope\": \"isolated-unit-probe-only\",\n";
        output << "  \"mixed_workload_formal_parameter_claim_allowed\": false,\n";
        output << "  \"publication_raw_block_contract_satisfied\": "
               << ((warmups == 3 && repetitions == 14) ? "true" : "false") << ",\n";
        output << "  \"all_profiles_correct\": true,\n";
        output << "  \"eval_mult_includes_relinearization\": true,\n";
        output << "  \"measured_rotation_index\": " << rotationIndices.front() << ",\n";
        output << "  \"required_exact_rotation_indices\": ";
        WriteIntArray(output, rotationIndices);
        output << ",\n";
        output << "  \"process_affinity_cpu_list\": ";
        WriteIntArray(output, processAffinityCpuList);
        output << ",\n";
        output << "  \"ciphertext_bytes\": " << fixture.ciphertextBytes() << ",\n";
        output << "  \"f1m_random_zero_sum_ciphertext_bytes\": "
               << fixture.f1mRandomZeroSumCiphertextBytes() << ",\n";
        output << "  \"f1m_encrypted_zero_dummy_ciphertext_bytes\": "
               << fixture.f1mEncryptedZeroDummyCiphertextBytes() << ",\n";
        output << "  \"rotation_key_bytes\": " << fixture.rotationKeyBytes() << ",\n";
        output << "  \"eval_mult_key_bytes\": " << fixture.evalMultKeyBytes() << ",\n";
        output << "  \"operations\": {\n";
        for (std::size_t index = 0; index < kPrimitiveNames.size(); ++index) {
            const auto name = std::string(kPrimitiveNames[index]);
            WriteSummary(
                output,
                name,
                summaries.at(name),
                index + 1 != kPrimitiveNames.size());
        }
        output << "  },\n";
        output << "  \"raw_measurement_blocks\": {\n";
        output << "    \"schema_version\": "
                  "\"dynamic-cssc-publication-raw-measurement-blocks-v1\",\n";
        output << "    \"clock\": \"std::chrono::steady_clock\",\n";
        output << "    \"clock_unit\": \"nanosecond\",\n";
        output << "    \"primitive_names\":";
        WriteStringArray(output, kPrimitiveNames);
        output << ",\n";
        output << "    \"warmup_block_count\":" << warmups << ",\n";
        output << "    \"measurement_block_count\":" << repetitions << ",\n";
        output << "    \"measurement_stop_rule\":\""
               << ((repetitions == 14)
                       ? kMeasurementStopRule
                       : "exploratory-fixed-count-not-publication-authority")
               << "\",\n";
        output << "    \"operation_order_seed\":" << kOperationOrderSeed << ",\n";
        output << "    \"operation_order_method\":\"" << kOperationOrderMethod << "\",\n";
        output << "    \"warmup_blocks\":";
        WriteBlocks(output, warmupBlocks, "      ");
        output << ",\n";
        output << "    \"blocks\":";
        WriteBlocks(output, measurementBlocks, "      ");
        output << "\n  }\n";
        output << "}\n";
        output.flush();
        if (!output) {
            std::cerr << "microbench output write failed\n";
            return 4;
        }
        std::cout << outputPath << '\n';
        return 0;
    }
    catch (const std::exception& exception) {
        std::cerr << "openfhe_microbench failed: " << exception.what() << '\n';
        return 1;
    }
}
