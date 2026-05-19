"""
Amazon Bedrock provider.
Supports: anthropic.claude-*, amazon.titan-*, meta.llama-*, mistral.* via AWS.
Uses boto3 async client via run_in_executor (boto3 has no native async).
"""
import time, asyncio, logging, json
import boto3
from llm.base_provider import BaseLLMProvider, LLMResponse

logger = logging.getLogger(__name__)


class AmazonBedrockProvider(BaseLLMProvider):
    def __init__(self, config):
        bedrock_cfg = config.llm.amazon_bedrock
        secrets = config.secrets.amazon_bedrock

        session_kwargs = {"region_name": bedrock_cfg.region}
        if not bedrock_cfg.use_iam_role and secrets.get("aws_access_key_id"):
            session_kwargs.update({
                "aws_access_key_id": secrets["aws_access_key_id"],
                "aws_secret_access_key": secrets["aws_secret_access_key"],
            })

        self._client = boto3.client("bedrock-runtime", **session_kwargs)
        self._model_id = bedrock_cfg.model_id
        self._max_retries = config.llm.max_retries
        self._timeout = config.llm.timeout_seconds

    @property
    def provider_name(self) -> str:
        return "amazon_bedrock"

    def _invoke_sync(self, body: dict) -> dict:
        """Sync call — will be run in executor."""
        response = self._client.invoke_model(
            modelId=self._model_id,
            body=json.dumps(body),
            contentType="application/json",
            accept="application/json",
        )
        return json.loads(response["body"].read())

    async def complete(self, system_prompt, user_message,
                       response_format="json", max_tokens=1000, temperature=0.1) -> LLMResponse:
        start = time.monotonic()
        sp = system_prompt
        if response_format == "json":
            sp += "\n\nRespond ONLY with a valid JSON object. No preamble, no markdown fences."

        # Build body based on model family
        if "anthropic.claude" in self._model_id:
            body = {
                "anthropic_version": "bedrock-2023-05-31",
                "system": sp,
                "messages": [{"role": "user", "content": user_message}],
                "max_tokens": max_tokens,
                "temperature": temperature,
            }
        elif "meta.llama" in self._model_id:
            body = {
                "prompt": f"<|system|>{sp}<|end|><|user|>{user_message}<|end|><|assistant|>",
                "max_gen_len": max_tokens,
                "temperature": temperature,
            }
        else:
            # Generic fallback — works for Titan, Mistral
            body = {
                "inputText": f"{sp}\n\nUser: {user_message}\nAssistant:",
                "textGenerationConfig": {"maxTokenCount": max_tokens, "temperature": temperature},
            }

        for attempt in range(self._max_retries):
            try:
                loop = asyncio.get_event_loop()
                result = await asyncio.wait_for(
                    loop.run_in_executor(None, self._invoke_sync, body),
                    timeout=self._timeout,
                )
                # Extract text based on model family
                if "anthropic.claude" in self._model_id:
                    content = result["content"][0]["text"]
                    tokens = result.get("usage", {}).get("input_tokens", 0) + \
                              result.get("usage", {}).get("output_tokens", 0)
                elif "meta.llama" in self._model_id:
                    content = result.get("generation", "")
                    tokens = result.get("prompt_token_count", 0) + result.get("generation_token_count", 0)
                else:
                    content = result.get("results", [{}])[0].get("outputText", "")
                    tokens = 0
                return LLMResponse(
                    content=content,
                    provider=self.provider_name,
                    model=self._model_id,
                    tokens_used=tokens,
                    latency_ms=int((time.monotonic() - start) * 1000),
                )
            except Exception as e:
                logger.warning(f"Bedrock attempt {attempt+1} failed: {e}")
                if attempt < self._max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
        raise RuntimeError("Bedrock failed after retries")

    async def health_check(self) -> bool:
        try:
            r = await self.complete("You are a test.", "Say OK", max_tokens=5)
            return bool(r.content)
        except Exception:
            return False
