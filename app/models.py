"""
Pydantic models for request/response validation.
"""

from pydantic import BaseModel, Field, field_validator
from typing import Optional


class LoginRequest(BaseModel):
    """Credentials for web dashboard login."""
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=256)


class LoginResponse(BaseModel):
    """Response returned upon successful authentication."""
    success: bool = True
    username: str
    message: str = "Přihlášení úspěšné"


class UserInfoResponse(BaseModel):
    """Information about currently authenticated session user."""
    authenticated: bool
    username: Optional[str] = None


class ResourceUpdateRequest(BaseModel):
    """Request body for updating container resource limits."""

    memory_mb: Optional[int] = Field(
        None, ge=6, le=131072, description="RAM limit in megabytes (min 6, max 128GB)"
    )
    cpu_cores: Optional[float] = Field(
        None, gt=0, le=128, description="CPU cores allocation (e.g. 1.5)"
    )
    force: bool = Field(
        False,
        description="Force apply even if OOM risk is detected",
    )

    @field_validator("memory_mb")
    @classmethod
    def validate_memory(cls, v: Optional[int]) -> Optional[int]:
        if v is not None and v < 6:
            raise ValueError("Minimum memory is 6 MB (Docker requirement)")
        return v

    @field_validator("cpu_cores")
    @classmethod
    def validate_cpu(cls, v: Optional[float]) -> Optional[float]:
        if v is not None and v <= 0:
            raise ValueError("CPU cores must be a positive number")
        if v is not None and v > 128:
            raise ValueError("CPU cores cannot exceed 128")
        return v


class ResourceUpdateResponse(BaseModel):
    """Response for successful resource update."""

    success: bool = True
    container_id: str
    applied_limits: dict
    compose_file_updated: bool = False
    compose_file_path: Optional[str] = None


class OOMRiskResponse(BaseModel):
    """Response when OOM risk is detected."""

    error: str = "OOM_RISK_DETECTED"
    message: str
    current_usage_mb: float
    requested_limit_mb: int
    requires_confirmation: bool = True


class ContainerInfo(BaseModel):
    """Container information with resource usage and limits."""

    id: str
    name: str
    status: str
    image: str
    memory_limit_mb: Optional[float] = None
    memory_usage_mb: Optional[float] = None
    cpu_limit_cores: Optional[float] = None
    cpu_usage_percent: Optional[float] = None
    is_compose: bool = False
    compose_file: Optional[str] = None
    compose_service: Optional[str] = None


class ErrorResponse(BaseModel):
    """Generic error response."""

    detail: str
