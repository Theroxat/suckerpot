"""Static checks of the release workflow and the image verification script (M28)."""

import re
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
SENSORS = "ssh rdp telnet web redis docker mysql mssql adb smb sip synology".split()
IMAGES = ["redis", "migrate", "ingest", "api", "collector", "hubproxy", "demo"] + [
    f"sensor-{n}" for n in SENSORS
]


def _load() -> dict[str, Any]:
    data = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    data["triggers"] = data.pop(True, None) or data.get("on")  # PyYAML reads `on:` as True
    return data  # type: ignore[no-any-return]


def test_only_a_version_tag_or_a_manual_run_triggers_it() -> None:
    triggers = _load()["triggers"]
    assert set(triggers) == {"push", "workflow_dispatch"}
    assert triggers["push"] == {"tags": ["v*.*.*"]}  # no branch, no pull request


def test_permissions_are_read_only_at_the_top_and_signing_is_confined_to_merge_and_manifest() -> (
    None
):
    wf = _load()
    assert wf["permissions"] == {"contents": "read"}
    for name, job in wf["jobs"].items():
        perms = job.get("permissions", {})
        assert ("id-token" in perms) == (name in {"merge", "manifest"}), name
        assert perms.get("packages") in (None, "read", "write"), name
        # Only the attach job may write to the repository (release assets), and nothing else.
        if name == "attach":
            assert perms == {"contents": "write"}
        else:
            assert perms.get("contents", "read") == "read", name


def test_every_image_is_built_for_both_architectures() -> None:
    build = _load()["jobs"]["build"]["strategy"]["matrix"]
    assert build["image"] == IMAGES
    assert {p["arch"]: p["runner"] for p in build["platform"]} == {
        "amd64": "ubuntu-24.04",
        "arm64": "ubuntu-24.04-arm",
    }
    assert _load()["jobs"]["merge"]["strategy"]["matrix"]["image"] == IMAGES


def test_publishing_steps_are_gated_and_a_branch_run_pushes_nothing() -> None:
    wf = _load()
    for job in ("merge", "smoke", "manifest", "attach"):
        assert wf["jobs"][job]["if"] == "needs.prepare.outputs.publish == 'true'"
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "refs/tags/v*) version=$REF_NAME; publish=true" in text
    # The only place an image leaves the runner is the publish branch of the build step.
    assert text.count("push=true") == 1
    assert "push=false" in text
    login_steps = [
        s
        for job in wf["jobs"].values()
        for s in job["steps"]
        if "docker login" in str(s.get("run", ""))
    ]
    gated = [s for s in login_steps if s.get("if")]
    assert gated and len(gated) == 1  # build; merge and smoke are gated by their job


def test_no_latest_tag_and_the_mandatory_attestations() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert not re.search(r"[:=]latest\b", text)
    for needle in ("--provenance=mode=max", "--sbom=true", "BUILD_KIND=image", "cosign sign --yes"):
        assert needle in text
    assert '--tag "$NAME:$VERSION" --tag "$NAME:${MINOR}"' in text


def test_third_party_actions_are_pinned_by_sha_and_tools_by_digest() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    for use in re.findall(r"uses:\s*(\S+)", text):
        assert re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", use), use
    assert re.search(r"BUILDKIT_IMAGE: \S+@sha256:[0-9a-f]{64}", text)
    assert re.search(r'COSIGN_AMD64_SHA256: "[0-9a-f]{64}"', text)


def test_smoke_install_uses_a_throwaway_project() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "PROJECT: sp-release-smoke" in text
    assert "--sensors ssh,web --admin-password-stdin" in text
    assert '--project "$PROJECT" --prefix "$PROJECT"' in text


def test_verify_script_pins_cosign_and_checks_the_workflow_identity() -> None:
    script = (ROOT / "scripts" / "verify-images.sh").read_text(encoding="utf-8")
    assert re.search(r'COSIGN_IMAGE="\S+@sha256:[0-9a-f]{64}"', script)
    assert "release\\\\.yml@refs/tags/" in script
    assert "https://token.actions.githubusercontent.com" in script
    for image in IMAGES:
        assert image in script
    assert "latest" not in script


def test_manifest_is_signed_keyless_after_the_images_and_attached_after_the_smoke_test() -> None:
    jobs = _load()["jobs"]
    assert set(jobs["manifest"]["needs"]) == {"prepare", "merge"}
    assert set(jobs["attach"]["needs"]) == {"prepare", "manifest", "smoke"}
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "cosign sign-blob --yes --bundle release-manifest.json.sigstore.json" in text
    assert "cosign verify-blob --bundle release-manifest.json.sigstore.json" in text
    assert "selfhostr-release/1" in text
    for field in ("version", "commit", "images", "network_defaults_sha256", "auto_min_age_h"):
        assert field in text
    assert "released_at" in text
    assert "--clobber release-manifest.json release-manifest.json.sigstore.json" in text
    # The manifest lists exactly the images that are built and signed.
    assert jobs["manifest"]["env"]["IMAGES"].split() == IMAGES


def test_a_release_with_a_placeholder_key_is_refused_before_anything_is_built() -> None:
    wf = _load()
    steps = wf["jobs"]["prepare"]["steps"]
    guard = next(s for s in steps if "placeholder" in s.get("name", ""))
    run = guard["run"]
    assert "config/network-defaults.env" in run
    assert "<HUB_PUBLIC_KEY>" in run and "<FEED_PUBLIC_KEY>" in run
    assert 'if [ "$EVENT" = push ]' in run and "exit 1" in run
    # Every other job waits for prepare, so nothing is built or pushed first.
    for name in ("build", "merge", "manifest", "attach"):
        assert "prepare" in wf["jobs"][name]["needs"]


def test_the_placeholder_gate_matches_the_real_file_format() -> None:
    gate = re.compile(r"<HUB_PUBLIC_KEY>|<FEED_PUBLIC_KEY>|^[A-Z_]+=<[A-Z_]+>", re.MULTILINE)
    assert gate.search("NETWORK_HUB_KEY=<HUB_PUBLIC_KEY>\n")
    assert not gate.search(
        "NETWORK_HUB_KEY=AAAAbase64key=\nNETWORK_HUB_URL=https://hub.example.org\n"
    )
    assert (ROOT / "config" / "network-defaults.env").is_file()


def test_verify_release_pins_the_same_cosign_and_identity_as_the_images() -> None:
    images = (ROOT / "scripts" / "verify-images.sh").read_text(encoding="utf-8")
    release = (ROOT / "scripts" / "verify-release.sh").read_text(encoding="utf-8")
    pin = re.search(r'COSIGN_IMAGE="(\S+@sha256:[0-9a-f]{64})"', release)
    assert pin and f'COSIGN_IMAGE="{pin.group(1)}"' in images
    assert "verify-blob" in release and "--bundle" in release
    assert "release\\\\.yml@refs/tags/" in release
    assert "https://token.actions.githubusercontent.com" in release
