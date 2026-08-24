from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _workflow_step(source: str, name: str) -> str:
    marker = f"      - name: {name}\n"
    start = source.index(marker)
    end = source.find("\n      - name:", start + len(marker))
    return source[start:] if end == -1 else source[start:end]


def test_p0a_build_pipelines_fail_closed() -> None:
    workflows = {
        ".github/workflows/p0a-rotation-probe.yml": (
            "Build pinned OpenFHE",
            "Build probes",
        ),
        ".github/workflows/day2-microbench.yml": ("Build OpenFHE and probes",),
    }
    for path, names in workflows.items():
        workflow = (ROOT / path).read_text()
        for name in names:
            step = _workflow_step(workflow, name)
            assert "\n        shell: bash\n" in step


def test_openfhe_user_include_contract_is_complete() -> None:
    cmake = (ROOT / "cpp/CMakeLists.txt").read_text()
    include_block = cmake.split("include_directories(", 1)[1].split(")", 1)[0]
    assert include_block.lstrip().startswith("SYSTEM")
    assert "${OpenFHE_INCLUDE}/binfhe" in cmake


def test_openfhe_microbench_serialization_smoke_is_mandatory() -> None:
    cmake = (ROOT / "cpp/CMakeLists.txt").read_text()
    build_script = (ROOT / "scripts/build_cpp.sh").read_text()
    source = (ROOT / "cpp/microbench.cpp").read_text()

    assert "openfhe_microbench_serialization_smoke" in cmake
    assert 'ctest --test-dir "$BUILD_DIR" --output-on-failure' in build_script
    assert '#include "key/key-ser.h"' in source
    assert '#include "scheme/bfvrns/bfvrns-ser.h"' in source


def test_rotation_probe_reads_counts_from_bfvrns_parameters() -> None:
    probe = (ROOT / "cpp/rotation_probe.cpp").read_text()
    assert "dynamic_pointer_cast<CryptoParametersBFVRNS>" in probe
    assert "cryptoParameters->GetEvalAddCount()" in probe
    assert "cryptoParameters->GetKeySwitchCount()" in probe


def test_p0a_workflow_selects_the_rotation_noise_profile() -> None:
    workflow = (ROOT / ".github/workflows/p0a-rotation-probe.yml").read_text()
    assert "noise_budget_profiles" in workflow
    assert "p0a_rotation" in workflow
    assert "--noise-budget-profile p0a_rotation" in workflow
    assert "['openfhe']['multiplicative_depth']" not in workflow
    assert "['openfhe']['eval_add_count']" not in workflow
    assert "['openfhe']['key_switch_count']" not in workflow
    probe = (ROOT / "cpp/rotation_probe.cpp").read_text()
    assert "noise_budget_profile" in probe
