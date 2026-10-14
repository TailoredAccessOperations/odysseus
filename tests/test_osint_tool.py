"""Tests for the OSINT GEOINT tool (src/agent_tools/osint_tools.py).

Filename contains neither ``mcp`` nor a security token, so this classifies as
``area_uncategorized``; rename to include an area keyword if a home exists.
"""

import base64
import json
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@pytest.fixture()
def osint(tmp_path, monkeypatch):
    """Load osint_tools with the app dependency chain stubbed out."""
    core = types.ModuleType("core")
    core.__path__ = []
    atomic = types.ModuleType("core.atomic_io")

    def atomic_write_json(path, data, *, indent=None):
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = f"{path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=indent or 1)
        tmp.replace(path)

    atomic.atomic_write_json = atomic_write_json
    constants = types.ModuleType("src.constants")
    constants.__path__ = []
    constants.DATA_DIR = str(tmp_path)
    src_pkg = types.ModuleType("src")
    src_pkg.__path__ = [str(Path(__file__).resolve().parents[1] / "src")]
    # Stub src.agent_tools as an empty package: importing the submodule would
    # otherwise run the package __init__, which pulls in the whole agent
    # dependency tree (tool_utils -> src.constants -> ...).
    tools_pkg = types.ModuleType("src.agent_tools")
    tools_pkg.__path__ = [str(Path(__file__).resolve().parents[1] / "src" / "agent_tools")]

    for name, mod in (
        ("core", core),
        ("core.atomic_io", atomic),
        ("src", src_pkg),
        ("src.constants", constants),
        ("src.agent_tools", tools_pkg),
    ):
        monkeypatch.setitem(sys.modules, name, mod)

    sys.modules.pop("src.agent_tools.osint_tools", None)
    import importlib

    mod = importlib.import_module("src.agent_tools.osint_tools")
    return mod


PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
)


# -- format sniffing ------------------------------------------------------

@pytest.mark.parametrize(
    "prefix,expected",
    [
        (b"\xff\xd8\xff\xe0", "image/jpeg"),
        (b"\x89PNG\r\n\x1a\n", "image/png"),
        (b"GIF87a", "image/gif"),
        (b"GIF89a", "image/gif"),
        (b"BM", "image/bmp"),
        (b"RIFF\x00\x00\x00\x00WEBPVP8 ", "image/webp"),
        (b"II*\x00", "image/tiff"),
        (b"MM\x00*", "image/tiff"),
    ],
)
def test_sniffs_known_formats(osint, prefix, expected):
    assert osint.sniff_image_type(prefix + b"\x00" * 32) == expected


@pytest.mark.parametrize("data", [b"hello world", b"", b"<html>", b"\x00\x01\x02"])
def test_rejects_non_images(osint, data):
    assert osint.sniff_image_type(data) is None


# -- decoding -------------------------------------------------------------

def test_decodes_raw_base64(osint):
    assert osint.decode_image_argument(base64.b64encode(PNG).decode()) == PNG


def test_decodes_data_uri(osint):
    uri = "data:image/png;base64," + base64.b64encode(PNG).decode()
    assert osint.decode_image_argument(uri) == PNG


def test_decodes_wrapped_base64(osint):
    """Models often wrap long base64 payloads; newlines must not break it."""
    encoded = base64.b64encode(PNG).decode()
    wrapped = "\n".join(encoded[i : i + 8] for i in range(0, len(encoded), 8))
    assert osint.decode_image_argument(wrapped) == PNG


def test_rejects_empty_data_uri(osint):
    with pytest.raises(ValueError):
        osint.decode_image_argument("data:image/png;base64,")


def test_rejects_invalid_base64(osint):
    with pytest.raises(ValueError):
        osint.decode_image_argument("!!!not base64!!!")


# -- argument validation --------------------------------------------------

@pytest.fixture()
def tool(osint):
    return osint.OsintLocateTool()


@pytest.mark.asyncio
async def test_rejects_missing_image(tool):
    result = await tool.execute("{}", {})
    assert result["exit_code"] == 1
    assert "image_base64" in result["error"]


@pytest.mark.asyncio
async def test_rejects_non_object_json(tool):
    result = await tool.execute("[1,2,3]", {})
    assert result["exit_code"] == 1


@pytest.mark.asyncio
async def test_rejects_bad_base64(tool):
    result = await tool.execute('{"image_base64": "!!!"}', {})
    assert result["exit_code"] == 1
    assert "base64" in result["error"]


@pytest.mark.asyncio
async def test_rejects_empty_image(tool):
    result = await tool.execute('{"image_base64": ""}', {})
    assert result["exit_code"] == 1


@pytest.mark.asyncio
async def test_rejects_oversize_image(tool, monkeypatch):
    monkeypatch.setattr(tool.__class__.__module__ and __import__(
        "src.agent_tools.osint_tools", fromlist=["MAX_IMAGE_BYTES"]
    ), "MAX_IMAGE_BYTES", 16)
    result = await tool.execute(
        json.dumps({"image_base64": base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"0" * 64).decode()}),
        {},
    )
    assert result["exit_code"] == 1
    assert "over the" in result["error"]


@pytest.mark.asyncio
async def test_rejects_unsupported_format(tool):
    payload = base64.b64encode(b"this is plain text, not an image").decode()
    result = await tool.execute(json.dumps({"image_base64": payload}), {})
    assert result["exit_code"] == 1
    assert "unsupported image format" in result["error"]


@pytest.mark.asyncio
async def test_accepts_bare_string_argument(tool, monkeypatch):
    """A non-JSON string is treated as the image itself, like get_weather."""
    captured = {}

    async def fake_analyze(data, mime):
        captured["data"], captured["mime"] = data, mime
        return {"guess": {"lat": 1.0, "lon": 2.0, "confidence": 0.9}, "reasoning": "ok"}

    monkeypatch.setattr(tool, "_analyze", fake_analyze)
    result = await tool.execute(base64.b64encode(PNG).decode(), {})
    assert result["exit_code"] == 0
    assert captured["mime"] == "image/png"
    assert json.loads(result["output"])["lat"] == 1.0


# -- response shaping -----------------------------------------------------

def test_shape_flattens_upstream_envelope(osint):
    payload = {
        "guess": {
            "lat": 48.8584, "lon": 2.2945, "confidence": 0.82,
            "radiusKm": 2.0, "placeName": "Paris", "country": "France",
            "clues": ["Eiffel Tower silhouette"] * 20,
        },
        "reasoning": "Landmark match.",
        "engine": "workers-ai:@cf/qwen/qwen3.8-27b",
    }
    out = osint.OsintLocateTool._shape(payload)
    assert out["lat"] == 48.8584 and out["lon"] == 2.5 - 0.2055
    assert out["place"] == "Paris"
    assert out["radius_km"] == 2.0
    assert out["engine"].startswith("workers-ai:")
    assert len(out["clues"]) == 8, "clues must be capped"


def test_shape_tolerates_missing_guess(osint):
    out = osint.OsintLocateTool._shape({"reasoning": "no data"})
    assert out["lat"] is None and out["clues"] == []


def test_shape_accepts_snake_case_radius(osint):
    out = osint.OsintLocateTool._shape({"guess": {"radius_km": 5}})
    assert out["radius_km"] == 5


def test_shape_survives_non_dict_guess(osint):
    out = osint.OsintLocateTool._shape({"guess": None, "reasoning": "x"})
    assert out["confidence"] is None


@pytest.mark.asyncio
async def test_error_from_analyze_is_passed_through(tool, monkeypatch):
    async def boom(data, mime):
        return {"error": "upstream said no", "exit_code": 1}

    monkeypatch.setattr(tool, "_analyze", boom)
    result = await tool.execute(base64.b64encode(PNG).decode(), {})
    assert result["exit_code"] == 1
    assert result["error"] == "upstream said no"


@pytest.mark.asyncio
async def test_never_raises_into_the_loop(tool, monkeypatch):
    async def boom(data, mime):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(tool, "_analyze", boom)
    result = await tool.execute(base64.b64encode(PNG).decode(), {})
    assert result["exit_code"] == 1
    assert "kaboom" in result["error"]


# -- Bedrock backend -------------------------------------------------------

def test_gateway_is_the_default_backend(osint, monkeypatch):
    # An existing deployment with no env set must keep using the gateway.
    monkeypatch.delenv(osint.BACKEND_ENV, raising=False)
    assert osint.bedrock_selected() is False


def test_bedrock_requires_explicit_opt_in(osint, monkeypatch):
    monkeypatch.setenv(osint.BACKEND_ENV, "bedrock")
    assert osint.bedrock_selected() is True


def test_backend_match_ignores_case_and_padding(osint, monkeypatch):
    monkeypatch.setenv(osint.BACKEND_ENV, "  BedRock ")
    assert osint.bedrock_selected() is True


def test_bedrock_region_falls_back_through_aws_standard_names(osint, monkeypatch):
    # AWS_REGION wins, then AWS_DEFAULT_REGION (what the AWS SDKs and CLI set),
    # then the built-in default.
    monkeypatch.delenv("AWS_REGION", raising=False)
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-west-2")
    assert osint.bedrock_region() == "eu-west-2"
    monkeypatch.setenv("AWS_REGION", "us-west-2")
    assert osint.bedrock_region() == "us-west-2"
    monkeypatch.delenv("AWS_REGION")
    monkeypatch.delenv("AWS_DEFAULT_REGION")
    assert osint.bedrock_region() == osint.DEFAULT_AWS_REGION


def test_bedrock_model_uses_an_inference_profile_by_default(osint, monkeypatch):
    # The default is a cross-region inference profile, not a bare foundation
    # model id: Bedrock requires the profile form for most Anthropic models.
    monkeypatch.delenv(osint.BEDROCK_MODEL_ENV, raising=False)
    assert osint.bedrock_model().startswith("us.")
    monkeypatch.setenv(osint.BEDROCK_MODEL_ENV, "my-profile")
    assert osint.bedrock_model() == "my-profile"


def test_strip_code_fence_handles_json_and_bare_payloads(osint):
    # Vision models fence JSON often enough that assuming a bare payload would
    # fail on otherwise-correct answers.
    assert osint._strip_code_fence('{"a":1}') == '{"a":1}'
    assert osint._strip_code_fence('```json\n{"a":1}\n```') == '{"a":1}'
    assert osint._strip_code_fence('```\n{"a":1}\n```') == '{"a":1}'


def test_normalize_bedrock_produces_the_gateway_envelope(osint):
    out = osint.OsintLocateTool._normalize_bedrock(
        '{"lat": 35.68, "lon": 139.69, "confidence": 0.9, "radiusKm": 3, '
        '"placeName": "Tokyo", "country": "Japan", "clues": ["signage"]}',
        "model-x",
    )
    # _shape() is backend-agnostic, so the normalized envelope must carry the
    # coordinates under `guess` exactly as the gateway does.
    shaped = osint.OsintLocateTool._shape(out)
    assert shaped["lat"] == 35.68 and shaped["lon"] == 139.69
    assert shaped["place"] == "Tokyo"
    assert shaped["engine"] == "bedrock:model-x"


def test_normalize_bedrock_tolerates_null_fields(osint):
    out = osint.OsintLocateTool._normalize_bedrock(
        '{"lat": null, "lon": null, "confidence": 0.0, "clues": []}', "m",
    )
    shaped = osint.OsintLocateTool._shape(out)
    assert shaped["lat"] is None and shaped["confidence"] == 0.0


def test_normalize_bedrock_coerces_string_clues_to_a_list(osint):
    # A string clue would otherwise be sliced character-wise by _shape's [:8].
    out = osint.OsintLocateTool._normalize_bedrock(
        '{"lat": 1, "lon": 2, "clues": "single clue"}', "m",
    )
    shaped = osint.OsintLocateTool._shape(out)
    assert shaped["clues"] == ["single clue"]


def test_normalize_bedrock_rejects_non_json(osint):
    out = osint.OsintLocateTool._normalize_bedrock("I cannot geolocate this.", "m")
    assert out["exit_code"] == 1
    assert "non-JSON" in out["error"]


def test_normalize_bedrock_rejects_non_object_json(osint):
    out = osint.OsintLocateTool._normalize_bedrock("[1, 2, 3]", "m")
    assert out["exit_code"] == 1
    assert "non-object" in out["error"]


@pytest.mark.asyncio
@pytest.mark.parametrize("mime", ["image/bmp", "image/tiff"])
async def test_bedrock_rejects_formats_it_cannot_read(osint, tool, monkeypatch, mime):
    # sniff_image_type accepts bmp/tiff, but Bedrock has no format for them.
    # Must be rejected explicitly rather than sent with a wrong format label.
    monkeypatch.setenv(osint.BACKEND_ENV, "bedrock")
    out = await tool._analyze_bedrock(b"BM....", mime)
    assert out["exit_code"] == 1
    assert mime in out["error"]


@pytest.mark.asyncio
async def test_bedrock_failure_is_not_silently_replaced_by_the_gateway(tool, monkeypatch):
    # A fallback here would report success while hiding a misconfigured
    # backend and doubling cost and latency on every call.
    import src.agent_tools.osint_tools as mod

    monkeypatch.setenv(mod.BACKEND_ENV, "bedrock")

    async def bedrock_boom(data, mime):
        return {"error": "bedrock misconfigured", "exit_code": 1}

    async def gateway_called(data, mime):
        raise AssertionError("gateway must not be reached when bedrock is selected")

    monkeypatch.setattr(tool, "_analyze_bedrock", bedrock_boom)
    monkeypatch.setattr(tool, "_analyze", gateway_called)
    result = await tool.execute(base64.b64encode(PNG).decode(), {})
    assert result["exit_code"] == 1
    assert result["error"] == "bedrock misconfigured"


@pytest.mark.asyncio
async def test_execute_routes_to_bedrock_when_selected(tool, monkeypatch):
    import src.agent_tools.osint_tools as mod

    monkeypatch.setenv(mod.BACKEND_ENV, "bedrock")
    seen = {}

    async def fake_bedrock(data, mime):
        seen["called"] = (mime, len(data))
        return {"guess": {"lat": 1.0, "lon": 2.0, "confidence": 0.5}, "engine": "bedrock:m"}

    async def gateway_called(data, mime):
        raise AssertionError("gateway must not be reached")

    monkeypatch.setattr(tool, "_analyze_bedrock", fake_bedrock)
    monkeypatch.setattr(tool, "_analyze", gateway_called)
    result = await tool.execute(base64.b64encode(PNG).decode(), {})
    assert result["exit_code"] == 0
    assert seen["called"][0] == "image/png"
    assert json.loads(result["output"])["lat"] == 1.0


@pytest.mark.asyncio
async def test_execute_uses_the_gateway_when_bedrock_not_selected(tool, monkeypatch):
    import src.agent_tools.osint_tools as mod

    monkeypatch.delenv(mod.BACKEND_ENV, raising=False)
    called = []

    async def fake_gateway(data, mime):
        called.append(mime)
        return {"guess": {"lat": 3.0, "lon": 4.0, "confidence": 0.4}}

    async def bedrock_called(data, mime):
        raise AssertionError("bedrock must not be reached by default")

    monkeypatch.setattr(tool, "_analyze", fake_gateway)
    monkeypatch.setattr(tool, "_analyze_bedrock", bedrock_called)
    result = await tool.execute(base64.b64encode(PNG).decode(), {})
    assert result["exit_code"] == 0
    assert called == ["image/png"]