"""
Project Aegis - LLM Security Proxy
FastAPI-based WAF for AI with prompt injection detection and DLP

NOW WITH ML CLASSIFIER SUPPORT!
"""

from fastapi import FastAPI, Request, HTTPException, Header, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator
import time
from datetime import datetime
from typing import Dict, Any, Optional
import httpx
import uuid
import os
from opentelemetry import trace
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import ConsoleSpanExporter, BatchSpanProcessor

# Import security components
from db import SecurityLogbook, EventType, SeverityLevel
from GuardToolkit import GuardManager, ThreatType

# Import configuration (with fallback)
try:
    from config import settings
except ImportError:
    # Fallback if config.py doesn't exist
    class FallbackSettings:
        allowed_origins_list = ["http://localhost:8501", "http://localhost:3000"]
        database_path = "aegis_security.db"
        block_on_injection = True
        redact_pii = True
        max_requests_per_minute = 60
        max_response_tokens = 2000
        max_prompt_length = 10000
        enable_rate_limiting = True
        enable_ml_classifier = False
        ml_model_path = "models/classifier.onnx"
        ml_tokenizer_path = "distilbert-base-uncased"
    settings = FallbackSettings()

# Initialize OpenTelemetry
provider = TracerProvider()
processor = BatchSpanProcessor(ConsoleSpanExporter())
provider.add_span_processor(processor)
trace.set_tracer_provider(provider)
tracer = trace.get_tracer(__name__)

app = FastAPI(
    title="Project Aegis",
    version="1.0.0",
    description="LLM Security Proxy with Prompt Injection Detection and DLP (ML Enhanced)"
)

# CORS middleware with restricted origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-Client-ID", "Authorization", "X-Use-ML"],
)

# Initialize the security logbook and guard manager WITH ML SUPPORT
logbook = SecurityLogbook(db_path=settings.database_path)

# Initialize guard with ML configuration
guard_manager = GuardManager(
    use_ml=settings.enable_ml_classifier,
    model_path=settings.ml_model_path if settings.enable_ml_classifier else None,
    tokenizer_path=settings.ml_vectorizer_path if settings.enable_ml_classifier else None
)

# Print ML status on startup
print("\n" + "="*60)
print("Project Aegis - Security Initialization")
print("="*60)
print(f"ML Classifier: {'✅ ENABLED' if settings.enable_ml_classifier else '⚠️  DISABLED (rules only)'}")
if settings.enable_ml_classifier:
    print(f"Model Path: {settings.ml_model_path}")
    print(f"Tokenizer: {settings.ml_vectorizer_path}")
print("="*60 + "\n")

# Simple in-memory rate limiting (replace with Redis in production)
request_counts = {}


# Pydantic models for request validation (Pydantic V2)
class GenerateRequest(BaseModel):
    """Request model with validation"""
    prompt: str = Field(..., min_length=1, max_length=10000)
    model: Optional[str] = Field(default="gpt-3.5-turbo", max_length=100)
    max_tokens: Optional[int] = Field(default=1000, ge=1, le=4096)
    temperature: Optional[float] = Field(default=0.7, ge=0.0, le=2.0)
    
    @field_validator('prompt')
    @classmethod
    def validate_prompt(cls, v: str) -> str:
        if not v.strip():
            raise ValueError('Prompt cannot be empty or whitespace only')
        return v.strip()
    
    @field_validator('model')
    @classmethod
    def validate_model(cls, v: Optional[str]) -> Optional[str]:
        if v:
            allowed_models = ['gpt-3.5-turbo', 'gpt-4', 'claude-2', 'claude-3']
            if v not in allowed_models:
                raise ValueError(f'Model must be one of: {", ".join(allowed_models)}')
        return v


def check_rate_limit(client_id: str) -> bool:
    """Simple rate limiting check"""
    if not settings.enable_rate_limiting:
        return True
    
    current_minute = int(time.time() / 60)
    key = f"{client_id}:{current_minute}"
    
    if key not in request_counts:
        request_counts[key] = 0
    
    request_counts[key] += 1
    
    # Clean up old entries (keep last 5 minutes)
    old_keys = [
        k for k in request_counts.keys() 
        if int(k.split(':')[1]) < current_minute - 5
    ]
    for old_key in old_keys:
        del request_counts[old_key]
    
    return request_counts[key] <= settings.max_requests_per_minute


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add security headers to all responses"""
    response = await call_next(request)
    
    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    
    return response


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    """Main security middleware for timing and logging"""
    start_time = time.time()
    request_id = str(uuid.uuid4())
    
    # Extract client ID from headers or generate one
    client_id = request.headers.get("X-Client-ID", request.client.host if request.client else "unknown")
    
    # Add request ID to request state
    request.state.request_id = request_id
    request.state.client_id = client_id
    
    try:
        response = await call_next(request)
        latency_ms = (time.time() - start_time) * 1000
        
        # Add custom headers
        response.headers["X-Aegis-Latency"] = f"{latency_ms:.2f}ms"
        response.headers["X-Aegis-Version"] = "1.0.0"
        response.headers["X-Request-ID"] = request_id
        
        return response
    except Exception as e:
        latency_ms = (time.time() - start_time) * 1000
        
        # Log error event
        try:
            logbook.log_event(
                event_type=EventType.SYSTEM_ERROR,
                severity=SeverityLevel.HIGH,
                user_id=client_id,
                session_id=request_id,
                action_taken="Request failed",
                processing_time_ms=latency_ms,
                blocked=True,
                metadata={"error": str(e), "error_type": type(e).__name__}
            )
        except Exception as log_error:
            print(f"Failed to log error: {log_error}")
        
        raise


@app.get("/")
async def root():
    """Health check endpoint"""
    ml_status = "enabled" if settings.enable_ml_classifier else "disabled"
    ml_available = False
    
    if settings.enable_ml_classifier and guard_manager.inbound_guard.ml_model:
        ml_available = guard_manager.inbound_guard.ml_model.is_available
    
    return {
        "status": "ok",
        "service": "Project Aegis",
        "version": "1.0.0",
        "description": "LLM Security Proxy (ML Enhanced)",
        "ml_classifier": {
            "enabled": settings.enable_ml_classifier,
            "available": ml_available,
            "status": ml_status
        }
    }


@app.get("/health")
async def health_check():
    """Detailed health check"""
    ml_stats = guard_manager.get_ml_stats()
    
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "components": {
            "database": "operational",
            "guard_system": "operational",
            "ml_classifier": {
                "enabled": settings.enable_ml_classifier,
                "available": guard_manager.inbound_guard.ml_model is not None and 
                            guard_manager.inbound_guard.ml_model.is_available,
                "stats": ml_stats
            }
        }
    }


@app.get("/policy")
async def get_policy():
    """Get current security policy configuration"""
    return {
        "block_on_injection": settings.block_on_injection,
        "redact_pii": settings.redact_pii,
        "max_requests_per_minute": settings.max_requests_per_minute,
        "max_response_tokens": settings.max_response_tokens,
        "max_prompt_length": settings.max_prompt_length,
        "ml_classifier": {
            "enabled": settings.enable_ml_classifier,
            "threshold": settings.ml_threshold if settings.enable_ml_classifier else None,
            "available": guard_manager.inbound_guard.ml_model is not None and
                        guard_manager.inbound_guard.ml_model.is_available
        }
    }


@app.post("/v1/generate")
async def generate_completion(
    request: GenerateRequest,
    req: Request,
    x_client_id: str = Header(None, alias="X-Client-ID"),
    x_use_ml: bool = Header(None, alias="X-Use-ML")  # Allow per-request ML override
):
    """
    Main endpoint for LLM completion with security checks
    Now supports optional per-request ML override!
    """
    start_time = time.time()
    client_id = x_client_id or req.state.client_id
    request_id = req.state.request_id
    
    # Determine if ML should be used (header overrides config)
    use_ml = x_use_ml if x_use_ml is not None else settings.enable_ml_classifier
    
    try:
        # Rate limiting check
        if not check_rate_limit(client_id):
            logbook.log_event(
                event_type=EventType.RATE_LIMIT,
                severity=SeverityLevel.MEDIUM,
                user_id=client_id,
                session_id=request_id,
                prompt=request.prompt[:100],
                action_taken="Rate limit exceeded",
                processing_time_ms=(time.time() - start_time) * 1000,
                blocked=True
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded"
            )
        
        # Inbound security check with optional ML
        with tracer.start_as_current_span("inbound_security_check") as span:
            span.set_attribute("prompt_length", len(request.prompt))
            span.set_attribute("ml_enabled", use_ml)
            
            prompt_check = guard_manager.check_prompt(request.prompt, use_ml=use_ml)
            
            span.set_attribute("threat_detected", not prompt_check.passed)
            span.set_attribute("threat_type", prompt_check.threat_type.value)
            span.set_attribute("ml_used", prompt_check.details.get("ml_used", False))
        
        # Block if threat detected and blocking is enabled
        if not prompt_check.passed and settings.block_on_injection:
            processing_time_ms = (time.time() - start_time) * 1000
            
            # Map ThreatType to EventType
            event_type_map = {
                ThreatType.PROMPT_INJECTION: EventType.PROMPT_INJECTION,
                ThreatType.JAILBREAK: EventType.PROMPT_INJECTION,
                ThreatType.DATA_EXFILTRATION: EventType.PROMPT_INJECTION,
            }
            event_type = event_type_map.get(prompt_check.threat_type, EventType.PROMPT_INJECTION)
            
            # Map Severity to SeverityLevel
            severity_map = {
                "critical": SeverityLevel.CRITICAL,
                "high": SeverityLevel.HIGH,
                "medium": SeverityLevel.MEDIUM,
                "low": SeverityLevel.LOW,
            }
            severity = severity_map.get(prompt_check.severity.value, SeverityLevel.HIGH)
            
            logbook.log_event(
                event_type=event_type,
                severity=severity,
                user_id=client_id,
                session_id=request_id,
                prompt=request.prompt[:1000],
                detected_patterns=prompt_check.matched_patterns,
                action_taken="Request blocked",
                processing_time_ms=processing_time_ms,
                blocked=True,
                metadata={
                    "confidence": prompt_check.confidence,
                    "details": prompt_check.details,
                    "ml_used": use_ml
                }
            )
            
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "Security policy violation",
                    "threat_type": prompt_check.threat_type.value,
                    "severity": prompt_check.severity.value,
                    "message": prompt_check.details.get("message"),
                    "request_id": request_id
                }
            )
        
        # Mock LLM response (replace with actual LLM call in production)
        with tracer.start_as_current_span("llm_generation") as span:
            span.set_attribute("model", request.model)
            
            # This is a mock response - replace with actual LLM API call
            mock_response = f"This is a mock response to: {request.prompt[:50]}... (In production, this would call the actual LLM)"
        
        # Outbound security check
        with tracer.start_as_current_span("outbound_security_check") as span:
            response_check = guard_manager.check_response(
                mock_response,
                redact=settings.redact_pii,
                max_tokens=settings.max_response_tokens
            )
            
            span.set_attribute("pii_detected", not response_check.passed)
            span.set_attribute("redacted", response_check.sanitized_text is not None)
        
        # Use sanitized response if available
        final_response = response_check.sanitized_text or mock_response
        
        # Log successful request
        processing_time_ms = (time.time() - start_time) * 1000
        logbook.log_event(
            event_type=EventType.NORMAL_REQUEST,
            severity=SeverityLevel.LOW,
            user_id=client_id,
            session_id=request_id,
            prompt=request.prompt[:1000],
            response=final_response[:1000],
            processing_time_ms=processing_time_ms,
            blocked=False,
            metadata={
                "model": request.model,
                "pii_detected": not response_check.passed,
                "ml_used": use_ml
            }
        )
        
        return {
            "id": request_id,
            "model": request.model,
            "response": final_response,
            "usage": {
                "prompt_tokens": len(request.prompt.split()),
                "completion_tokens": len(final_response.split()),
            },
            "security": {
                "prompt_check": {
                    "passed": prompt_check.passed,
                    "ml_used": use_ml
                },
                "response_check": {
                    "passed": response_check.passed,
                    "redacted": response_check.sanitized_text is not None
                },
                "processing_time_ms": round(processing_time_ms, 2)
            }
        }
    
    except HTTPException:
        raise
    except Exception as e:
        processing_time_ms = (time.time() - start_time) * 1000
        
        logbook.log_event(
            event_type=EventType.SYSTEM_ERROR,
            severity=SeverityLevel.HIGH,
            user_id=client_id,
            session_id=request_id,
            prompt=request.prompt[:1000],
            action_taken="Internal error",
            processing_time_ms=processing_time_ms,
            blocked=True,
            metadata={"error": str(e), "error_type": type(e).__name__}
        )
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )


@app.get("/stats/ml")
async def ml_statistics():
    """Get ML classifier performance statistics"""
    if not settings.enable_ml_classifier:
        return {
            "enabled": False,
            "message": "ML classifier is not enabled"
        }
    
    stats = guard_manager.get_ml_stats()
    
    return {
        "enabled": True,
        "available": guard_manager.inbound_guard.ml_model is not None and
                    guard_manager.inbound_guard.ml_model.is_available,
        "stats": stats,
        "config": {
            "threshold": settings.ml_threshold,
            "max_length": settings.ml_max_length,
            "model_path": settings.ml_model_path,
            "tokenizer": settings.ml_vectorizer_path
        }
    }


# Instrument with OpenTelemetry
FastAPIInstrumentor.instrument_app(app)

if __name__ == "__main__":
    import uvicorn
    print("=" * 60)
    print("Starting Project Aegis - LLM Security Proxy (ML Enhanced)")
    print("=" * 60)
    print(f"Documentation: http://localhost:8000/docs")
    print(f"Health Check: http://localhost:8000/health")
    print(f"Policy Info: http://localhost:8000/policy")
    print(f"ML Stats: http://localhost:8000/stats/ml")
    print("=" * 60)
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")