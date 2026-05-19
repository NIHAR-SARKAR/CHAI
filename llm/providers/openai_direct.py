"""Direct OpenAI API provider (non-Azure)."""
import time, asyncio, logging
from openai import AsyncOpenAI
from llm.base_provider import BaseLLMProvider, LLMResponse

logger = logging.getLogger(__name__)


class OpenAIDirectProvider(BaseLLMProvider):
    def __init__(self, config):
        self._client = AsyncOpenAI(
            api_key=config.secrets.openai.get("api_key", ""),
            base_url=config.llm.openai.api_base,
        )
        self._model = config.llm.openai.model
        self._max_retries = config.llm.max_retries
        self._timeout = config.llm.timeout_seconds

    @property
    def provider_name(self) -> str:
        return "openai"

    async def complete(self, system_prompt, user_message,
                       response_format="json", max_tokens=1000, temperature=0.1) -> LLMResponse:
        fmt = {"type": "json_object"} if response_format == "json" else {"type": "text"}
        start = time.monotonic()
        for attempt in range(self._max_retries):
            try:
                resp = await asyncio.wait_for(
                    self._client.chat.completions.create(
                        model=self._model,
                        messages=[
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_message},
                        ],
                        response_format=fmt,
                        max_tokens=max_tokens,
                        temperature=temperature,
                    ),
                    timeout=self._timeout,
                )
                return LLMResponse(
                    content=resp.choices[0].message.content,
                    provider=self.provider_name,
                    model=self._model,
                    tokens_used=resp.usage.total_tokens if resp.usage else 0,
                    latency_ms=int((time.monotonic() - start) * 1000),
                )
            except Exception as e:
                logger.warning(f"OpenAI attempt {attempt+1} failed: {e}")
                if attempt < self._max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
        raise RuntimeError("OpenAI failed after retries")

    async def health_check(self) -> bool:
        try:
            r = await self._client.chat.completions.create(
                model=self._model,
                messages=[{"role": "user", "content": "ping"}],
                max_tokens=5,
            )
            return bool(r.choices)
        except Exception:
            return False
