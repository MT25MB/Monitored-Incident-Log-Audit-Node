"""Offline tests for the provider chain, including local Ollama and fallback telemetry."""

from __future__ import annotations

import sys
from pathlib import Path

from pydantic import BaseModel

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.config import (  # noqa: E402
    InMemoryTelemetrySink,
    PacingConfig,
    Provider,
    ProviderCallError,
    ProviderConfig,
    RetryConfig,
    Settings,
    invoke_structured,
)
from src.schemas import StepTrace  # noqa: E402


class Answer(BaseModel):
    ok: bool


class FailingAdapter:
    provider = Provider.GEMINI

    def complete_json(self, **kwargs):
        raise ProviderCallError("synthetic provider failure")


class WorkingAdapter:
    provider = Provider.OLLAMA

    def complete_json(self, **kwargs):
        return {"ok": True}, {"prompt_tokens": 4, "completion_tokens": 2}


def _settings() -> Settings:
    return Settings(
        providers=(
            ProviderConfig(Provider.GEMINI, "gemini-test", "key", "https://invalid/v1"),
            ProviderConfig(
                Provider.OLLAMA,
                "llama3.1",
                None,
                "http://localhost:11434/v1",
                requires_api_key=False,
            ),
        ),
        pacing=PacingConfig(enabled=False),
        retry=RetryConfig(max_attempts=1, jitter_seconds=0.0),
    )


def test_ollama_disabled_by_default() -> None:
    settings = Settings.from_env({})
    ollama = [p for p in settings.providers if p.provider is Provider.OLLAMA]
    assert len(ollama) == 1
    assert ollama[0].available is False


def test_ollama_config_from_env() -> None:
    settings = Settings.from_env(
        {"OLLAMA_ENABLED": "true", "LLM_PROVIDER_ORDER": "ollama"}
    )
    config = settings.providers[0]
    assert config.provider is Provider.OLLAMA
    assert config.base_url == "http://localhost:11434/v1"
    assert config.model == "llama3.1"
    assert config.api_key is None
    assert config.available is True


def test_fallback_triggered_and_cost_stay_zero() -> None:
    sink = InMemoryTelemetrySink()
    result = invoke_structured(
        Answer,
        system_prompt="Answer with JSON.",
        user_prompt="Return ok true.",
        settings=_settings(),
        sink=sink,
        adapters={
            Provider.GEMINI: FailingAdapter(),
            Provider.OLLAMA: WorkingAdapter(),
        },
        sleep_fn=lambda _seconds: None,
    )

    assert result.data.ok is True
    assert result.trace.provider == "ollama"
    assert result.trace.fallback_from == "gemini"
    assert result.trace.fallback_triggered is True
    assert result.trace.estimated_cost_usd == 0.0
    assert isinstance(sink.traces[0], StepTrace)


def test_no_fallback_when_primary_succeeds() -> None:
    settings = Settings(
        providers=(
            ProviderConfig(
                Provider.OLLAMA,
                "llama3.1",
                None,
                "http://localhost:11434/v1",
                requires_api_key=False,
            ),
        ),
        pacing=PacingConfig(enabled=False),
        retry=RetryConfig(max_attempts=1),
    )
    result = invoke_structured(
        Answer,
        system_prompt="Answer with JSON.",
        user_prompt="Return ok true.",
        settings=settings,
        sink=InMemoryTelemetrySink(),
        adapters={Provider.OLLAMA: WorkingAdapter()},
    )
    assert result.trace.fallback_from is None
    assert result.trace.fallback_triggered is False
