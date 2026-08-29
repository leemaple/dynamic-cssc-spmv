from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _function_body(source: str, name: str, next_name: str) -> str:
    start = source.index(name)
    end = source.index(next_name, start)
    return source[start:end]


def test_runner_keeps_legacy_cli_and_adds_two_closed_route_a_modes() -> None:
    source = (ROOT / "cpp/openfhe_query_runner.cpp").read_text()

    assert 'constexpr char kRouteAModeArgument[] = "route-a-mode";' in source
    assert 'value == "producer"' in source
    assert 'value == "replay"' in source
    assert "RunLegacyProducer(args)" in source
    assert "RunRouteAProducer(args)" in source
    assert "RunRouteAReplay(args)" in source
    assert (
        "RequireExactArgumentKeys(\n"
        "                args,\n"
        '                {"request",\n'
        '                 "result",\n'
        '                 "object-dir",\n'
        '                 "control-write-fd",\n'
        '                 "control-read-fd"}'
    ) in source


def test_route_a_replay_has_one_package_input_and_no_request_argument() -> None:
    source = (ROOT / "cpp/openfhe_query_runner.cpp").read_text()
    main = _function_body(source, "int main(", "catch (const std::exception& exception)")

    assert (
        '{"route-a-mode",\n'
        '                 "package-dir",\n'
        '                 "result",\n'
        '                 "object-dir",\n'
        '                 "control-write-fd",\n'
        '                 "control-read-fd"}'
    ) in main
    replay_argument_block = main[main.index("RunnerMode::RouteAReplay") :]
    assert 'args.at("package-dir")' in replay_argument_block
    assert 'args.at("request")' not in replay_argument_block


def test_route_a_replay_deserializes_exact_objects_without_generation_or_encryption() -> None:
    source = (ROOT / "cpp/openfhe_query_runner.cpp").read_text()
    replay = _function_body(source, "int RunRouteAReplay(", "int main(")

    for forbidden in (
        "MakeContext(",
        "GenCryptoContext",
        "KeyGen(",
        "EvalMultKeyGen",
        "EvalRotateKeyGen",
        "Encrypt(",
    ):
        assert forbidden not in replay
    for required in (
        "CryptoContextFactory<DCRTPoly>::ReleaseAllContexts()",
        "DeserializeOpenFHE",
        "DeserializeEvalMultKey",
        "DeserializeEvalAutomorphismKey",
        "ParseCombinedEvaluationKeyFrame",
        "ExecuteProgram",
        "context->Decrypt",
    ):
        assert required in replay


def test_openfhe_151_deserialization_and_member_lookup_compile_contract_is_exact() -> None:
    source = (ROOT / "cpp/openfhe_query_runner.cpp").read_text()
    deserialize = _function_body(
        source,
        "Value DeserializeOpenFHE(",
        "void DeserializeEvalMultKey(",
    )
    lookup = _function_body(
        source,
        "const RouteAPackageMember& UniqueRouteAPackageMember(",
        "std::string InputCategory(",
    )

    # OpenFHE 1.5.1's generic Serial::Deserialize overload returns void.
    assert "Serial::Deserialize(value, stream, SerType::BINARY);" in deserialize
    assert "!Serial::Deserialize" not in deserialize
    # Literal roles use a non-owning value so a temporary std::string cannot
    # trigger GCC's -Wdangling-reference diagnostic on the returned member.
    assert lookup.count("std::string_view role") == 2


def test_route_a_producer_retains_context_keys_and_one_unchanged_day1b_frame() -> None:
    source = (ROOT / "cpp/openfhe_query_runner.cpp").read_text()
    producer = _function_body(source, "int RunRouteAProducer(", "int RunRouteAReplay(")
    frame = _function_body(
        source,
        "std::string BuildCombinedEvaluationKeyFrame(",
        "std::uint64_t ReadUint64BigEndian(",
    )

    for required in (
        'SerializeOpenFHE(context, "crypto context")',
        "SerializeOpenFHE(\n                                              keyPair.secretKey,",
        '"secret key")',
        'SerializeOpenFHE(keyPair.publicKey, "public key")',
        "BuildCombinedEvaluationKeyFrame",
        '"route-a-private-replay-crypto-context"',
        '"route-a-private-replay-secret-key"',
        '"one-time-evaluation-key-material"',
    ):
        assert required in producer
    assert frame.count("AppendUint64BigEndian") == 2
    assert frame.count("DigestBytes(HashUtil::HashString") == 2
    assert "88 + rotationKeys.size() + evalMultKeys.size()" in frame
    assert "secret" not in frame.lower()
    assert "context" not in frame.lower()
    assert "public" not in frame.lower()


def test_route_a_result_splits_cloud_and_mode_specific_lifecycle_inventories() -> None:
    source = (ROOT / "cpp/openfhe_query_runner.cpp").read_text()

    assert '"cloud_program_operation_inventory"' in source
    assert '"lifecycle_operation_inventory"' in source
    for field in (
        "context_generation_count",
        "key_generation_count",
        "eval_mult_key_generation_count",
        "automorphism_key_generation_count",
        "encrypt_count",
        "crypto_context_deserialize_count",
        "secret_key_deserialize_count",
        "public_key_deserialize_count",
        "eval_mult_key_deserialize_count",
        "automorphism_key_deserialize_count",
        "input_ciphertext_deserialize_count",
        "decrypt_count",
    ):
        assert field in source
