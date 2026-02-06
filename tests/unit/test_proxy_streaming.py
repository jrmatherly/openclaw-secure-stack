"""Unit tests for proxy SSE streaming support."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from src.proxy.app import create_app
from src.sanitizer.sanitizer import PromptSanitizer

TOKEN = "test-token-streaming"


@pytest.fixture()
def rules_path(tmp_path: Path) -> str:
    rules = [
        {
            "id": "PI-001",
            "name": "test",
            "pattern": "(?i)ignore\\s+previous",
            "action": "strip",
            "description": "test",
        },
    ]
    p = tmp_path / "rules.json"
    p.write_text(json.dumps(rules))
    return str(p)


@pytest.fixture()
def app(rules_path: str) -> object:
    sanitizer = PromptSanitizer(rules_path)
    return create_app(
        upstream_url="http://upstream:3000",
        token=TOKEN,
        sanitizer=sanitizer,
    )


@pytest.mark.asyncio
async def test_non_streaming_request_returns_buffered(app: object) -> None:
    """Non-streaming requests return a normal buffered Response."""
    fake_response = httpx.Response(
        status_code=200,
        content=b'{"id":"chatcmpl-1","choices":[]}',
        headers={"content-type": "application/json"},
    )

    async def mock_request(*args, **kwargs):
        return fake_response

    transport = ASGITransport(app=app)  # type: ignore[arg-type]
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        with patch("src.proxy.app.httpx.AsyncClient") as mock_cls:
            mock_inst = AsyncMock()
            mock_inst.request = mock_request
            mock_inst.__aenter__ = AsyncMock(return_value=mock_inst)
            mock_inst.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_inst

            resp = await client.post(
                "/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {TOKEN}",
                    "Content-Type": "application/json",
                },
                content=json.dumps(
                    {
                        "model": "gpt-4o-mini",
                        "messages": [{"role": "user", "content": "Hi"}],
                    }
                ).encode(),
            )

    assert resp.status_code == 200
    assert resp.headers.get("content-type") == "application/json"


@pytest.mark.asyncio
async def test_streaming_request_returns_sse(app: object) -> None:
    """Streaming requests return text/event-stream."""
    chunks = [
        b'data: {"id":"chatcmpl-1","choices":[{"delta":{"content":"Hello"}}]}\n\n',
        b"data: [DONE]\n\n",
    ]

    async def aiter_bytes():
        for c in chunks:
            yield c

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.headers = httpx.Headers({"content-type": "text/event-stream"})
    mock_response.aiter_bytes = aiter_bytes
    mock_response.aclose = AsyncMock()

    transport = ASGITransport(app=app)  # type: ignore[arg-type]
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        with patch("src.proxy.app.httpx.AsyncClient") as mock_cls:
            mock_inst = AsyncMock()
            mock_inst.build_request = MagicMock(return_value=MagicMock())
            mock_inst.send = AsyncMock(return_value=mock_response)
            mock_inst.aclose = AsyncMock()
            mock_cls.return_value = mock_inst

            resp = await client.post(
                "/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {TOKEN}",
                    "Content-Type": "application/json",
                },
                content=json.dumps(
                    {
                        "model": "gpt-4o-mini",
                        "messages": [{"role": "user", "content": "Hi"}],
                        "stream": True,
                    }
                ).encode(),
            )

    assert resp.status_code == 200
    assert "text/event-stream" in resp.headers.get("content-type", "")
    body = resp.content.decode()
    assert "Hello" in body
    assert "[DONE]" in body
