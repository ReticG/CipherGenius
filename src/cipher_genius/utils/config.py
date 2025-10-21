"""Configuration management"""

import os
from typing import Optional
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    """Application settings"""

    # LLM Configuration
    openai_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    zhipuai_api_key: Optional[str] = None  # 智谱 AI API Key
    default_llm_provider: str = "openai"
    openai_model: str = "gpt-4-turbo-preview"
    anthropic_model: str = "claude-3-opus-20240229"
    zhipuai_model: str = "glm-4"  # GLM-4 模型
    embedding_model: str = "text-embedding-3-large"

    # Database Configuration
    qdrant_host: str = "localhost"
    qdrant_port: int = 6333
    qdrant_collection_name: str = "crypto_knowledge"
    database_url: str = "postgresql://postgres:password@localhost:5432/ciphergenius"
    redis_url: str = "redis://localhost:6379/0"

    # Application Settings
    debug: bool = True
    log_level: str = "INFO"
    api_host: str = "0.0.0.0"
    api_port: int = 8000

    # Generation Settings
    max_scheme_variants: int = 5
    default_timeout: int = 60
    enable_caching: bool = True

    # Security
    api_key_enabled: bool = False
    api_key: Optional[str] = None

    class Config:
        env_file = ".env"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance"""
    return Settings()
