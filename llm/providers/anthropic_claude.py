"""Anthropic Claude provider (direct API, not via Azure)."""
import time, asyncio, logging, json
import anthropic
from llm.base_provider import BaseLLMProvider, LLMResponse

logger = logging.getLogger(__name__)


class AnthropicClaudeProvider(BaseLLMProvider):
    def __init__(self, config):
        self._client = anthropic.AsyncAnthropic(
            api_key=config.secrets.anthropic.get("api_key", ""),
            base_url=config.llm.anthropic.api_base,
        )
        self._model = config.llm.anthropic.model
        self._max_retries = config.llm.max_retries
        self._timeout = config.llm.timeout_seconds

    @property
    def provider_name(self) -> str:
        return "anthropic"

    async def complete(self, system_prompt, user_message,
                       response_format="json", max_tokens=1000, temperature=0.1) -> LLMResponse:
        start = time.monotonic()
        # Anthropic doesn't have a JSON mode — instruct via system prompt
        sp = system_prompt
        if response_format == "json":
            sp += "\n\nRespond ONLY with a valid JSON object. No preamble, no markdown fences."

        for attempt in range(self._max_retries):
            try:
                resp = await asyncio.wait_for(
                    self._client.messages.create(
                        model=self._model,
                        system=sp,
                        messages=[{"role": "user", "content": user_message}],
                        max_tokens=max_tokens,
                        temperature=temperature,
                    ),
                    timeout=self._timeout,
                )
                content = resp.content[0].text
                tokens = (resp.usage.input_tokens + resp.usage.output_tokens) if resp.usage else 0
                return LLMResponse(
                    content=content,
                    provider=self.provider_name,
                    model=self._model,
                    tokens_used=tokens,
                    latency_ms=int((time.monotonic() - start) * 1000),
                )
            except Exception as e:
                logger.warning(f"Anthropic attempt {attempt+1} failed: {e}")
                if attempt < self._max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
        raise RuntimeError("Anthropic failed after retries")

    async def health_check(self) -> bool:
        try:
            r = await self._client.messages.create(
                model=self._model,
                messages=[{"role": "user", "content": "ping"}],
                max_tokens=5,
            )
            return bool(r.content)
        except Exception:
            return False
