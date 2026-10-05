// Included inside the query runner's anonymous namespace to reuse its validated
// OpenFHE primitives. This is a separate engineering protocol, not Route A.
using R1Clock = std::chrono::steady_clock;

std::uint64_t R1Elapsed(const R1Clock::time_point start) {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(R1Clock::now() - start).count();
}

struct R1CachedValue {
    Ciphertext<DCRTPoly> ciphertext;
    std::string plaintextHash;
    std::string ciphertextHash;
    std::uint64_t byteCount;
};

class R1Lifecycle {
    CryptoContext<DCRTPoly> context;
    KeyPair<DCRTPoly> keys;
    std::map<std::string, R1CachedValue> cache;
    std::set<std::int32_t> keyIndices;
    std::set<std::string> preparations;
    std::set<std::string> publications;
    std::string publication;
    std::uint32_t slots = 0;
    std::uint64_t keyBytes = 0;

    static void Receipt(json::Value& receipts, Allocator& a,
                        const std::string& direction, const std::string& kind,
                        const std::string& bytes) {
        json::Value item(json::kObjectType);
        AddString(item, "direction", direction, a);
        AddString(item, "kind", kind, a);
        AddString(item, "sha256", HashUtil::HashString(bytes), a);
        AddUInt(item, "bytes", bytes.size(), a);
        receipts.PushBack(item.Move(), a);
    }

    Ciphertext<DCRTPoly> RoundTrip(const Ciphertext<DCRTPoly>& ciphertext,
                                  json::Value& receipts, Allocator& a,
                                  const std::string& direction, const std::string& kind) {
        const auto bytes = SerializeOpenFHE(ciphertext, kind);
        Receipt(receipts, a, direction, kind, bytes);
        return DeserializeOpenFHE<Ciphertext<DCRTPoly>>(bytes, kind);
    }

    void CheckCache() const {
        for (const auto& entry : cache) {
            if (HashUtil::HashString(SerializeOpenFHE(entry.second.ciphertext, "cache check"))
                != entry.second.ciphertextHash) {
                Fail("R1 cached matrix ciphertext mutated during evaluation");
            }
        }
    }

public:
    void Setup(const json::Value& payload, json::Document& result) {
        RequireExactKeys(payload, {}, "R1 setup");
        if (context) Fail("R1 setup may only occur once");
        auto& a = result.GetAllocator();
        auto start = R1Clock::now();
        context = MakeContext();
        keys = context->KeyGen();
        if (!keys.good()) Fail("R1 key generation failed");
        context->EvalMultKeyGen(keys.secretKey);
        AddUInt(result, "key_generation_ns", R1Elapsed(start), a);
        start = R1Clock::now();
        json::Value receipts(json::kArrayType);
        const auto contextBytes = SerializeOpenFHE(context, "context");
        const auto publicBytes = SerializeOpenFHE(keys.publicKey, "public key");
        const auto multBytes = SerializeEvalMultKeys(context);
        for (const auto direction : {"B->A", "B->Cloud"}) {
            Receipt(receipts, a, direction, "context", contextBytes);
            static_cast<void>(DeserializeOpenFHE<CryptoContext<DCRTPoly>>(contextBytes, "context"));
        }
        Receipt(receipts, a, "B->A", "public-key", publicBytes);
        static_cast<void>(DeserializeOpenFHE<PublicKey<DCRTPoly>>(publicBytes, "public key"));
        Receipt(receipts, a, "B->Cloud", "multiplication-keys", multBytes);
        // OpenFHE key registries are process-global. The colocated sender has
        // already inserted this tag; install the actual received inventory,
        // instead of colliding with (or silently retaining) sender-side keys.
        context->ClearEvalMultKeys(keys.secretKey->GetKeyTag());
        DeserializeEvalMultKey(context, multBytes);
        keyBytes = contextBytes.size() + publicBytes.size() + multBytes.size();
        AddUInt(result, "private_secret_key_bytes",
                SerializeOpenFHE(keys.secretKey, "private storage only").size(), a);
        AddUInt(result, "serialization_roundtrip_ns", R1Elapsed(start), a);
        result.AddMember("wire_objects", receipts.Move(), a);
    }

    void Publish(const json::Value& payload, json::Document& result) {
        RequireExactKeys(payload, {"publication_id", "slot_count", "values"}, "R1 publication");
        if (!context) Fail("R1 publication before setup");
        const auto id = StringMember(payload, "publication_id", "publication ID");
        if (!PrintableIdentifier(id) || !publications.insert(id).second) {
            Fail("R1 publication ID reused or invalid");
        }
        const auto count = UIntMember(payload, "slot_count", "slot count");
        if (count == 0 || count > kSingleRowSlots || (slots != 0 && count != slots)) {
            Fail("R1 slot count changed or unsupported");
        }
        slots = count;
        const auto& values = Member(payload, "values", "values");
        if (!values.IsArray()) Fail("R1 values must be an array");
        auto& a = result.GetAllocator();
        json::Value receipts(json::kArrayType);
        std::map<std::string, R1CachedValue> next;
        std::uint64_t encryptions = 0, encryptionNs = 0, wireNs = 0;
        for (const auto& item : values.GetArray()) {
            RequireExactKeys(item, {"cache_key", "reencrypt", "values"}, "R1 matrix value");
            const auto key = StringMember(item, "cache_key", "cache key");
            const auto& refresh = Member(item, "reencrypt", "reencrypt");
            const auto& vector = Member(item, "values", "values");
            if (!PrintableIdentifier(key) || !refresh.IsBool() || !vector.IsArray()
                || vector.Size() != slots || next.count(key)) Fail("invalid R1 matrix value");
            std::vector<std::int64_t> packed;
            json::Value normalized(json::kArrayType);
            for (const auto& value : vector.GetArray()) {
                const auto lane = Normalize(StrictInteger(value, "matrix lane"));
                packed.push_back(lane);
                normalized.PushBack(json::Value().SetInt64(lane), a);
            }
            const auto hash = HashUtil::HashString(CanonicalJson(normalized));
            const auto previous = cache.find(key);
            if (!refresh.GetBool()) {
                if (previous == cache.end() || previous->second.plaintextHash != hash) {
                    Fail("R1 reuse of absent or changed matrix value");
                }
                next.emplace(key, previous->second);
            }
            else {
                auto start = R1Clock::now();
                const auto ct = context->Encrypt(keys.publicKey, context->MakePackedPlaintext(packed));
                if (!ct) Fail("R1 matrix encryption failed");
                encryptionNs += R1Elapsed(start);
                start = R1Clock::now();
                const auto bytes = SerializeOpenFHE(ct, "matrix ciphertext");
                Receipt(receipts, a, "A->Cloud", key, bytes);
                auto received = DeserializeOpenFHE<Ciphertext<DCRTPoly>>(bytes, "matrix ciphertext");
                next.emplace(key, R1CachedValue{received, hash,
                    HashUtil::HashString(SerializeOpenFHE(received, "cache identity")), bytes.size()});
                wireNs += R1Elapsed(start);
                ++encryptions;
            }
        }
        std::uint64_t oldBytes = 0, nextBytes = 0, transientBytes = 0;
        for (const auto& item : cache) oldBytes += item.second.byteCount;
        for (const auto& item : next) {
            nextBytes += item.second.byteCount;
            const auto old = cache.find(item.first);
            if (old == cache.end() || old->second.ciphertext != item.second.ciphertext) {
                transientBytes += item.second.byteCount;
            }
        }
        AddUInt(result, "old_matrix_serialized_bytes", oldBytes, a);
        AddUInt(result, "old_plus_new_unique_matrix_serialized_bytes", oldBytes + transientBytes, a);
        AddUInt(result, "matrix_serialized_bytes", nextBytes, a);
        AddUInt(result, "matrix_ciphertexts", next.size(), a);
        AddUInt(result, "matrix_encryptions", encryptions, a);
        AddUInt(result, "matrix_reused", next.size() - encryptions, a);
        AddUInt(result, "encryption_ns", encryptionNs, a);
        AddUInt(result, "serialization_roundtrip_ns", wireNs, a);
        cache = std::move(next);
        publication = id;
        result.AddMember("wire_objects", receipts.Move(), a);
    }

    void Query(const json::Value& payload, json::Document& result) {
        RequireExactKeys(payload, {"publication_id", "request", "value_keys"}, "R1 query");
        if (!context || publication.empty()
            || StringMember(payload, "publication_id", "publication ID") != publication) {
            Fail("R1 query publication binding mismatch");
        }
        const auto& request = Member(payload, "request", "query request");
        RequireExactKeys(request, {"bindings", "ciphertext_values", "key_generation_plan",
            "openfhe", "program", "schema_version"}, "R1 query request");
        RequireString(request, "schema_version", kRequestSchema, "query schema");
        ValidateOpenFHEProfile(Member(request, "openfhe", "profile"));
        const auto& program = Member(request, "program", "program");
        RequireExactKeys(program, {"ciphertext_inputs", "format", "nodes", "plaintext_masks",
            "result_ids", "rotation_catalog", "slot_count"}, "R1 program");
        RequireString(program, "format", kProgramSchema, "program schema");
        if (UIntMember(program, "slot_count", "slots") != slots) Fail("R1 query slot mismatch");
        const auto& bindings = Member(request, "bindings", "bindings");
        ValidateBindings(bindings, program);
        const auto& execution = Member(bindings, "execution_binding", "execution binding");
        if (StringMember(execution, "version_id", "version") != publication) Fail("R1 stale version");
        if (!preparations.insert(StringMember(bindings, "query_preparation_sha256", "preparation")).second) {
            Fail("R1 repeated query preparation");
        }
        const auto inputs = ParsePrivateInputs(Member(request, "ciphertext_values", "inputs"), slots);
        ValidateProgramInputs(Member(program, "ciphertext_inputs", "inputs"), inputs, slots);
        const auto rotations = ParseRotationCatalog(Member(program, "rotation_catalog", "rotations"), slots);
        const auto plan = ParseKeyGenerationPlan(Member(request, "key_generation_plan", "key plan"), bindings, rotations);
        const auto& valueKeys = Member(payload, "value_keys", "value keys");
        if (!valueKeys.IsObject()) Fail("R1 value keys must be object");
        auto& a = result.GetAllocator();
        json::Value receipts(json::kArrayType);
        auto start = R1Clock::now();
        CheckCache();
        std::uint64_t validationNs = R1Elapsed(start);
        std::vector<std::int32_t> additional;
        for (auto index : plan.requiredExactIndices) if (!keyIndices.count(index)) additional.push_back(index);
        start = R1Clock::now();
        if (!additional.empty()) context->EvalRotateKeyGen(keys.secretKey, additional);
        AddUInt(result, "new_rotation_key_generation_ns", R1Elapsed(start), a);
        AddUInt(result, "new_rotation_keys", additional.size(), a);
        start = R1Clock::now();
        if (!additional.empty()) {
            // A full inventory snapshot is sent on augmentation, not an estimated delta.
            const auto bytes = SerializeRotationKeyInventory(context);
            Receipt(receipts, a, "B->Cloud", "rotation-key-inventory", bytes);
            // The frame contains the full old+new inventory. Clear only this
            // session's tag so subsequent evaluation uses deserialized keys.
            context->ClearEvalAutomorphismKeys(keys.secretKey->GetKeyTag());
            DeserializeEvalAutomorphismKey(context, bytes);
            keyIndices.insert(additional.begin(), additional.end());
            keyBytes = SerializeOpenFHE(context, "context inventory").size()
                + SerializeOpenFHE(keys.publicKey, "pk inventory").size()
                + SerializeEvalMultKeys(context).size() + bytes.size();
        }
        std::uint64_t wireNs = R1Elapsed(start), encryptNs = 0;
        CiphertextMap ciphertexts;
        std::set<std::string> identifiers, usedKeys;
        OperationCounts counts;
        for (const auto& input : inputs) {
            Ciphertext<DCRTPoly> ct;
            if (input.role == "value") {
                const auto key = StringMember(valueKeys, input.ciphertextId.c_str(), "matrix cache key");
                const auto found = cache.find(key);
                json::Value vector(json::kArrayType);
                for (std::uint32_t lane = 0; lane < slots; ++lane) {
                    vector.PushBack(json::Value().SetInt64(input.values.at(lane)), a);
                }
                if (found == cache.end() || !usedKeys.insert(key).second
                    || found->second.plaintextHash != HashUtil::HashString(CanonicalJson(vector))) {
                    Fail("R1 query matrix input differs from publication");
                }
                ct = found->second.ciphertext;
            }
            else {
                start = R1Clock::now();
                ct = context->Encrypt(keys.publicKey, context->MakePackedPlaintext(input.values));
                if (!ct) Fail("R1 query encryption failed");
                encryptNs += R1Elapsed(start);
                ++counts.encrypt;
                start = R1Clock::now();
                ct = RoundTrip(ct, receipts, a, input.role == "query" ? "B->Cloud" : "A->Cloud", input.ciphertextId);
                wireNs += R1Elapsed(start);
            }
            identifiers.insert(input.ciphertextId);
            ciphertexts.emplace(input.ciphertextId, ct);
        }
        if (usedKeys.size() != cache.size() || valueKeys.MemberCount() != usedKeys.size()) {
            Fail("R1 matrix cache not used exactly once");
        }
        start = R1Clock::now();
        auto masks = ParsePlaintextMasks(context, Member(program, "plaintext_masks", "masks"), slots);
        const auto returned = ExecuteProgram(context, Member(program, "nodes", "nodes"), rotations,
            masks, ciphertexts, identifiers, counts);
        AddUInt(result, "evaluation_ns", R1Elapsed(start), a);
        if (returned != ParseResultIds(Member(program, "result_ids", "results"))) Fail("R1 result order mismatch");
        json::Value outputs(json::kObjectType);
        std::uint64_t decryptNs = 0;
        for (const auto& id : returned) {
            start = R1Clock::now();
            const auto ct = RoundTrip(ExistingCiphertext(ciphertexts, id, "result"), receipts, a, "Cloud->B", id);
            wireNs += R1Elapsed(start);
            start = R1Clock::now();
            Plaintext plaintext;
            if (!context->Decrypt(keys.secretKey, ct, &plaintext).isValid) Fail("R1 invalid decryption");
            ++counts.decrypt;
            plaintext->SetLength(kBatchSize);
            const auto lanes = plaintext->GetPackedValue();
            if (lanes.size() != kBatchSize) Fail("R1 packed decryption length changed");
            json::Value values(json::kArrayType);
            for (std::uint32_t lane = 0; lane < kBatchSize; ++lane) {
                const auto value = Normalize(lanes.at(lane));
                if (lane < slots) values.PushBack(json::Value().SetInt64(value), a);
                else if (value != 0) Fail("R1 result escaped effective row");
            }
            json::Value name(id.data(), static_cast<json::SizeType>(id.size()), a);
            outputs.AddMember(name.Move(), values.Move(), a);
            decryptNs += R1Elapsed(start);
        }
        start = R1Clock::now();
        CheckCache();
        validationNs += R1Elapsed(start);
        AddUInt(result, "cache_validation_ns", validationNs, a);
        AddUInt(result, "encryption_ns", encryptNs, a);
        AddUInt(result, "serialization_roundtrip_ns", wireNs, a);
        AddUInt(result, "decryption_ns", decryptNs, a);
        AddUInt(result, "query_encryptions", counts.encrypt, a);
        AddUInt(result, "decryptions", counts.decrypt, a);
        AddUInt(result, "key_inventory_serialized_bytes", keyBytes, a);
        AddString(result, "request_sha256", HashUtil::HashString(CanonicalJson(request)), a);
        result.AddMember("operations", BuildCloudProgramOperationInventory(counts, a), a);
        result.AddMember("outputs", outputs.Move(), a);
        result.AddMember("wire_objects", receipts.Move(), a);
    }
};

int RunR1Lifecycle() {
    R1Lifecycle session;
    std::uint64_t expected = 0;
    std::string line;
    while (std::getline(std::cin, line)) {
        const auto start = R1Clock::now();
        if (line.size() > kRequestByteMaximum) Fail("R1 command exceeds bounded frame");
        json::Document command;
        command.Parse<json::kParseValidateEncodingFlag>(line.data(), line.size());
        if (command.HasParseError()) Fail("R1 invalid JSON");
        RequireExactKeys(command, {"op", "payload", "schema_version", "sequence"}, "R1 command");
        RequireString(command, "schema_version", "r1-native-engineering-command-v1", "R1 schema");
        if (UIntMember(command, "sequence", "sequence") != expected++) Fail("R1 sequence mismatch");
        const auto op = StringMember(command, "op", "operation");
        json::Document result(json::kObjectType);
        auto& a = result.GetAllocator();
        AddString(result, "schema_version", "r1-native-engineering-receipt-v1", a);
        AddUInt(result, "sequence", expected - 1, a);
        AddString(result, "op", op, a);
        const auto& payload = Member(command, "payload", "payload");
        if (op == "setup") session.Setup(payload, result);
        else if (op == "publish") session.Publish(payload, result);
        else if (op == "query") session.Query(payload, result);
        else if (op == "close") RequireExactKeys(payload, {}, "R1 close");
        else Fail("R1 unknown operation");
        AddUInt(result, "native_handler_ns", R1Elapsed(start), a);
        struct rusage usage {};
        if (getrusage(RUSAGE_SELF, &usage) != 0) Fail("R1 getrusage failed");
        AddUInt(result, "native_peak_rss_platform_units", usage.ru_maxrss, a);
        AddString(result, "status", "pass", a);
        std::cout << CanonicalJson(result) << std::endl;
        if (op == "close") return 0;
    }
    Fail("R1 stream ended without explicit close");
}
