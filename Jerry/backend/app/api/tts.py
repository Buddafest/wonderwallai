"""
Jerry The Customer Service Bot — Text-to-Speech API
Proxies text to OpenAI TTS and returns audio/mpeg.
"""

import logging
import re

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.core.config import get_settings
from app.core.security import verify_widget_token

logger = logging.getLogger("jerry.tts")

router = APIRouter(tags=["TTS"])

VALID_VOICES = {"alloy", "echo", "fable", "onyx", "nova", "shimmer"}
EMOJI_RE = re.compile(r"[\U0001F600-\U0001F9FF\U00002700-\U000027BF\U0000FE00-\U0000FE0F\U0001FA00-\U0001FA6F\U0001FA70-\U0001FAFF\U00002600-\U000026FF\U0000200D\U00002B50\U000023CF-\U000023FA\U0001F1E0-\U0001F1FF]+", flags=re.UNICODE)


class TTSRequest(BaseModel):
    text: str = Field(..., max_length=4096)
    voice: str = Field(default="")
    lang: str = Field(default="en")


@router.post("/tts")
async def text_to_speech(req: TTSRequest, request: Request):
    """Convert text to speech via OpenAI TTS API. Requires widget JWT."""
    # Auth
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    token = auth[7:]
    payload = verify_widget_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")

    settings = get_settings()
    if not settings.openai_configured:
        raise HTTPException(status_code=503, detail="TTS not configured")

    # Clean text
    clean = EMOJI_RE.sub("", req.text).strip()
    clean = re.sub(r"\s{2,}", " ", clean)
    if not clean:
        raise HTTPException(status_code=400, detail="Empty text after cleaning")

    voice = req.voice if req.voice in VALID_VOICES else settings.openai_tts_voice

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                "https://api.openai.com/v1/audio/speech",
                headers={
                    "Authorization": f"Bearer {settings.openai_api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": settings.openai_tts_model,
                    "input": clean,
                    "voice": voice,
                    "response_format": "mp3",
                },
                timeout=30.0,
            )
            if resp.status_code != 200:
                logger.error(f"OpenAI TTS error {resp.status_code}: {resp.text[:200]}")
                raise HTTPException(status_code=502, detail="TTS generation failed")

            return StreamingResponse(
                iter([resp.content]),
                media_type="audio/mpeg",
                headers={"Cache-Control": "no-cache"},
            )
        except httpx.TimeoutException:
            raise HTTPException(status_code=504, detail="TTS request timed out")
