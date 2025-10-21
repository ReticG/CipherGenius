"""LLM interface for interacting with language models"""

import json
from typing import Optional, Dict, Any, List
from abc import ABC, abstractmethod

from cipher_genius.utils.config import get_settings
from cipher_genius.utils.cache import get_cache
from cipher_genius.utils.logger import get_logger

logger = get_logger(__name__)


class LLMInterface(ABC):
    """Abstract base class for LLM providers"""

    @abstractmethod
    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4000,
    ) -> str:
        """Generate text from prompt"""
        pass

    @abstractmethod
    def generate_json(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
    ) -> Dict[str, Any]:
        """Generate JSON response from prompt"""
        pass


class OpenAIInterface(LLMInterface):
    """OpenAI API interface"""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        settings = get_settings()
        self.api_key = api_key or settings.openai_api_key
        self.model = model or settings.openai_model

        if not self.api_key:
            raise ValueError("OpenAI API key not provided")

        try:
            from openai import OpenAI
            self.client = OpenAI(api_key=self.api_key)
        except ImportError:
            raise ImportError("openai package not installed. Install with: poetry add openai")

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4000,
    ) -> str:
        """Generate text from prompt"""
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )

        return response.choices[0].message.content

    def generate_json(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
    ) -> Dict[str, Any]:
        """Generate JSON response from prompt"""
        # Check cache first
        cache = get_cache()
        cached_result = cache.get(
            prompt=prompt,
            system_prompt=system_prompt or "",
            temperature=temperature,
            model=self.model
        )

        if cached_result is not None:
            logger.debug(f"Cache HIT for OpenAI request")
            return cached_result

        logger.debug(f"Cache MISS for OpenAI request, calling API")

        full_prompt = prompt + "\n\nRespond with valid JSON only."

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": full_prompt})

        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=temperature,
            response_format={"type": "json_object"},
        )

        content = response.choices[0].message.content
        result = json.loads(content)

        # Cache the result
        cache.set(
            prompt=prompt,
            system_prompt=system_prompt or "",
            response=result,
            temperature=temperature,
            model=self.model
        )

        return result


class AnthropicInterface(LLMInterface):
    """Anthropic API interface"""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        settings = get_settings()
        self.api_key = api_key or settings.anthropic_api_key
        self.model = model or settings.anthropic_model

        if not self.api_key:
            raise ValueError("Anthropic API key not provided")

        try:
            from anthropic import Anthropic
            self.client = Anthropic(api_key=self.api_key)
        except ImportError:
            raise ImportError("anthropic package not installed. Install with: poetry add anthropic")

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4000,
    ) -> str:
        """Generate text from prompt"""
        kwargs = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [{"role": "user", "content": prompt}],
        }

        if system_prompt:
            kwargs["system"] = system_prompt

        response = self.client.messages.create(**kwargs)
        return response.content[0].text

    def generate_json(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
    ) -> Dict[str, Any]:
        """Generate JSON response from prompt"""
        # Check cache first
        cache = get_cache()
        cached_result = cache.get(
            prompt=prompt,
            system_prompt=system_prompt or "",
            temperature=temperature,
            model=self.model
        )

        if cached_result is not None:
            logger.debug(f"Cache HIT for Anthropic request")
            return cached_result

        logger.debug(f"Cache MISS for Anthropic request, calling API")

        full_prompt = prompt + "\n\nRespond with valid JSON only."

        kwargs = {
            "model": self.model,
            "max_tokens": 4000,
            "temperature": temperature,
            "messages": [{"role": "user", "content": full_prompt}],
        }

        if system_prompt:
            kwargs["system"] = system_prompt

        response = self.client.messages.create(**kwargs)
        content = response.content[0].text

        # Extract JSON from markdown code blocks if present
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0].strip()
        elif "```" in content:
            content = content.split("```")[1].split("```")[0].strip()

        result = json.loads(content)

        # Cache the result
        cache.set(
            prompt=prompt,
            system_prompt=system_prompt or "",
            response=result,
            temperature=temperature,
            model=self.model
        )

        return result


class ZhipuAIInterface(LLMInterface):
    """智谱 AI (GLM) API interface"""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        settings = get_settings()
        self.api_key = api_key or settings.zhipuai_api_key
        self.model = model or settings.zhipuai_model

        if not self.api_key:
            raise ValueError("ZhipuAI API key not provided")

        try:
            from zhipuai import ZhipuAI
            self.client = ZhipuAI(api_key=self.api_key)
        except ImportError:
            raise ImportError("zhipuai package not installed. Install with: pip install zhipuai")

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4000,
    ) -> str:
        """Generate text from prompt"""
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )

        return response.choices[0].message.content

    def generate_json(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
    ) -> Dict[str, Any]:
        """Generate JSON response from prompt"""
        # Check cache first
        cache = get_cache()
        cached_result = cache.get(
            prompt=prompt,
            system_prompt=system_prompt or "",
            temperature=temperature,
            model=self.model
        )

        if cached_result is not None:
            logger.debug(f"Cache HIT for ZhipuAI request")
            return cached_result

        logger.debug(f"Cache MISS for ZhipuAI request, calling API")

        full_prompt = prompt + "\n\n请只返回有效的 JSON 格式。"

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": full_prompt})

        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=temperature,
        )

        content = response.choices[0].message.content

        # Extract JSON from markdown code blocks if present
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0].strip()
        elif "```" in content:
            content = content.split("```")[1].split("```")[0].strip()

        result = json.loads(content)

        # Cache the result
        cache.set(
            prompt=prompt,
            system_prompt=system_prompt or "",
            response=result,
            temperature=temperature,
            model=self.model
        )

        return result


def get_llm_interface(provider: Optional[str] = None) -> LLMInterface:
    """Get LLM interface based on provider"""
    settings = get_settings()
    provider = provider or settings.default_llm_provider

    if provider == "openai":
        return OpenAIInterface()
    elif provider == "anthropic":
        return AnthropicInterface()
    elif provider == "zhipuai" or provider == "glm":
        return ZhipuAIInterface()
    else:
        raise ValueError(f"Unknown LLM provider: {provider}")
