"""
Centralized configuration management for Project Aegis
ML CLASSIFIER NOW ENABLED!
"""
from pydantic_settings import BaseSettings
from typing import List
import secrets
import os


class Settings(BaseSettings):
    """Application settings with environment variable support"""
    
    # Application
    app_name: str = "Project Aegis"
    app_version: str = "1.0.0"
    debug: bool = False
    secret_key: str = secrets.token_urlsafe(32)
    
    # Database
    database_path: str = "aegis_security.db"
    db_connection_timeout: int = 30
    
    # CORS - Only allow specific origins in production
    allowed_origins: str = "http://localhost:8501,http://localhost:3000"
    
    # Security Policy
    block_on_injection: bool = True
    redact_pii: bool = True
    max_requests_per_minute: int = 60
    max_response_tokens: int = 2000
    max_prompt_length: int = 10000
    
    # Rate Limiting
    enable_rate_limiting: bool = True
    
    # Observability
    enable_tracing: bool = True
    log_level: str = "INFO"
    
    # Upstream LLM (for production)
    upstream_llm_url: str = "https://api.openai.com/v1/chat/completions"
    upstream_llm_api_key: str = ""
    
    # ML Classifier Settings - NOW ENABLED!
    enable_ml_classifier: bool = True  # ✅ CHANGED TO TRUE
    ml_model_path: str = "aegis_classifier.pkl"
    ml_vectorizer_path: str = "aegis_vectorizer.pkl"
    ml_threshold: float = 0.7
    ml_confidence_threshold: float = 0.65  # Minimum confidence to trust ML prediction
    
    @property
    def allowed_origins_list(self) -> List[str]:
        """Convert comma-separated origins to list"""
        return [origin.strip() for origin in self.allowed_origins.split(",")]
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


# Global settings instance
settings = Settings()