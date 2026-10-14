"""Visual GEOINT (OSINT) geolocation, routed through the MCP gateway pool.

Backed by the htp.sh OSINT endpoint, which runs a vision model over an
uploaded image and returns a coordinate guess with its reasoning and the
clues it used. Used for "where was this photo taken" style questions and for
checking whether an image in a chat matches a claimed location.

Transport
---------
Calls go through :func:`src.mcp_gateway.get_pool`, so every request is
round-robined across the configured gateway pool and fails over on error. That
keeps this tool's failure behaviour identical to every other gateway consumer
rather than hardcoding one upstream.

The upstream contract is ``POST <base>/osint/api/analyze`` taking either
``multipart/form-data`` with an ``image`` field or a raw ``image/*`` body, and
returning JSON with at least ``guess.lat``, ``guess.lon``, ``guess.confidence``
and ``reasoning``.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import logging
import os
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# Hard ceilings. The upstream model reads the whole image, so a large upload
# costs real money and wall-clock; refuse rather than silently truncating.
MAX_IMAGE_BYTES = int(os.getenv("ODYSSEUS_OSINT_MAX_BYTES", str(8 * 1024 * 1024)))
ANALYZE_PATH = os.getenv("ODYSSEUS_OSINT_PATH", "/osint/api/analyze")
# Measured live: a single small image took ~100s against the 27B vision model
# on a cold Workers AI start. The default has to clear that comfortably or
# every cold call fails as a timeout rather than succeeding slowly.
REQUEST_TIMEOUT = float(os.getenv("ODYSSEUS_OSINT_TIMEOUT", "240"))

_MAGIC = (
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"BM", "image/bmp"),
)


def sniff_image_type(data: bytes) -> Optional[str]:
    """Best-effort content type from magic bytes.

    Falls back to webp (RIFF....WEBP) and tiff, which do not have a fixed
    prefix. Returns None when nothing matches, so the caller can reject
    rather than send a mislabelled body.
    """
    for prefix, mime in _MAGIC:
        if data.startswith(prefix):
            return mime
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    if data[:4] in (b"II*\x00", b"MM\x00*"):
        return "image/tiff"
    return None


def decode_image_argument(value: str) -> bytes:
    """Decode a base64 image, or a ``data:`` URI, into raw bytes.

    Accepts a raw data URI so the model can pass through what the browser gave
    it without having to strip the prefix itself.
    """
    text = value.strip()
    if text.startswith("data:"):
        _, _, rest = text.partition(",")
        if not rest:
            raise ValueError("data URI has no payload after the comma")
        text = rest
    # Tolerate whitespace from wrapped payloads. Strip it before decoding so
    # validate=True can still reject genuinely malformed input.
    text = "".join(text.split())
    try:
        # validate=True is load-bearing: with validate=False, b64decode
        # silently discards non-alphabet characters, so "!!!" decodes to b""
        # and a malformed upload looks like an empty one.
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"image is not valid base64: {exc}") from exc


class OsintLocateTool:
    """Geolocate an image with a vision model and return its reasoning."""

    async def execute(self, content: str, ctx: dict) -> dict:
        try:
            args: Any = json.loads(content) if content.strip().startswith("{") else {"image_base64": content}
            if not isinstance(args, dict):
                return {"error": "osint_locate expects base64 image data or a JSON object", "exit_code": 1}

            raw = args.get("image_base64") or args.get("image") or args.get("data")
            if not isinstance(raw, str) or not raw.strip():
                return {"error": "osint_locate requires image_base64", "exit_code": 1}

            try:
                data = decode_image_argument(raw)
            except ValueError as exc:
                return {"error": str(exc), "exit_code": 1}

            if not data:
                return {"error": "osint_locate received an empty image", "exit_code": 1}
            if len(data) > MAX_IMAGE_BYTES:
                return {
                    "error": (
                        f"image is {len(data)} bytes, over the "
                        f"{MAX_IMAGE_BYTES}-byte OSINT limit; downscale first"
                    ),
                    "exit_code": 1,
                }

            mime = sniff_image_type(data)
            if mime is None:
                return {
                    "error": "unsupported image format; expected JPEG, PNG, GIF, BMP, WebP or TIFF",
                    "exit_code": 1,
                }

            result = await self._analyze(data, mime)
            if isinstance(result, dict) and "error" in result:
                return result

            payload = self._shape(result)
            return {
                "output": json.dumps(payload, ensure_ascii=False),
                "exit_code": 0,
                "evidence_status": "available",
            }
        except Exception as exc:  # tool boundary: never raise into the loop
            logger.warning("OSINT locate failed: %s", exc)
            return {"error": f"OSINT geolocation failed: {exc}", "exit_code": 1}

    async def _analyze(self, data: bytes, mime: str) -> Any:
        """POST the image to the gateway pool. Raw image body, not multipart.

        The upstream accepts either; raw keeps the pool path a simple JSON/text
        call and avoids re-encoding bytes into a multipart envelope.
        """
        import httpx

        from src.mcp_gateway import GatewayError, get_pool

        pool = get_pool()
        # Acquire once: a second acquire() advances the round-robin cursor and
        # could resolve the path against one endpoint while posting to another.
        endpoint = pool.acquire()
        path = pool.resolve_path(endpoint.base_url, "osint_analyze") or ANALYZE_PATH
        url = endpoint.base_url.rstrip("/") + path
        try:
            async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT, follow_redirects=False) as client:
                resp = await client.post(
                    url,
                    content=data,
                    headers={
                        "Content-Type": mime,
                        "X-Odysseus-Tool": "osint_locate",
                    },
                )
        except GatewayError as exc:
            return {"error": f"OSINT gateway unavailable: {exc}", "exit_code": 1}
        except Exception as exc:
            return {"error": f"OSINT request failed: {exc}", "exit_code": 1}

        if resp.status_code >= 400:
            return {
                "error": f"OSINT endpoint returned HTTP {resp.status_code}: {resp.text[:200]}",
                "exit_code": 1,
            }
        try:
            return resp.json()
        except ValueError:
            return {"error": f"OSINT endpoint returned non-JSON: {resp.text[:200]}", "exit_code": 1}

    @staticmethod
    def _shape(result: Dict[str, Any]) -> Dict[str, Any]:
        """Flatten the upstream envelope into the fields a model actually uses.

        The upstream nests coordinates under ``guess`` and wraps free text in
        ``reasoning``; keep the clues too, because they are the auditable
        evidence for the coordinate rather than a bare number the model has to
        take on faith.
        """
        guess = result.get("guess") or {}
        return {
            "lat": guess.get("lat"),
            "lon": guess.get("lon"),
            "confidence": guess.get("confidence"),
            "radius_km": guess.get("radiusKm", guess.get("radius_km")),
            "place": guess.get("placeName", guess.get("place_name")),
            "country": guess.get("country"),
            "clues": (guess.get("clues") or [])[:8],
            "reasoning": result.get("reasoning"),
            "engine": result.get("engine"),
        }