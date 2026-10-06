"""
Docker Limits Manager — FastAPI Application.

Provides REST API for dynamically managing Docker container
resource limits (CPU, RAM) without restart or rebuild.
Authentication supports web dashboard sessions (user/password) and X-API-Key.
"""

import asyncio
import logging

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .auth import (
    verify_auth,
    verify_credentials,
    create_session_token,
    verify_session_token,
    get_client_ip,
)
from .config import SESSION_COOKIE_NAME, SESSION_LIFETIME_HOURS
from .docker_manager import DockerManager
from .models import (
    ResourceUpdateRequest,
    LoginRequest,
    LoginResponse,
    UserInfoResponse,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("limits")

# FastAPI application
app = FastAPI(
    title="Docker Limits Manager",
    description="Dynamically manage Docker container resource limits",
    version="1.0.0",
    docs_url=None,  # Disable Swagger UI in production
    redoc_url=None,  # Disable ReDoc in production
)

# CORS — restrict to same origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=[],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT"],
    allow_headers=["X-API-Key", "Content-Type"],
)

# Docker manager instance
docker_mgr = DockerManager()


# ── Health Check (no auth) ──────────────────────────────────────────────

@app.get("/api/health")
async def health_check():
    """Health check endpoint — no authentication required."""
    return {"status": "healthy", "service": "docker-limits-manager"}


# ── User Auth Endpoints ─────────────────────────────────────────────────

@app.post("/api/v1/auth/login", response_model=LoginResponse)
async def login(req: LoginRequest, request: Request, response: Response):
    """
    Authenticate user with username and password from .env.
    Sets secure HttpOnly session cookie.
    """
    client_ip = get_client_ip(request)
    success, err_msg = verify_credentials(req.username, req.password, client_ip)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=err_msg,
        )

    token = create_session_token(req.username)
    max_age = SESSION_LIFETIME_HOURS * 3600

    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        max_age=max_age,
        httponly=True,
        samesite="lax",
        secure=False,  # Accessible over internal LAN or Traefik SSL termination
        path="/",
    )

    logger.info("User '%s' successfully logged in from %s", req.username, client_ip)
    return LoginResponse(
        success=True,
        username=req.username,
        message="Přihlášení úspěšné",
    )


@app.post("/api/v1/auth/logout")
async def logout(response: Response):
    """Clear session cookie to log out."""
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path="/",
    )
    return {"success": True, "message": "Byli jste úspěšně odhlášeni"}


@app.get("/api/v1/auth/me", response_model=UserInfoResponse)
async def get_me(request: Request):
    """Check current authentication status."""
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if token:
        payload = verify_session_token(token)
        if payload and payload.get("sub"):
            return UserInfoResponse(authenticated=True, username=payload["sub"])
    return UserInfoResponse(authenticated=False, username=None)


# ── List Containers ─────────────────────────────────────────────────────

@app.get("/api/v1/containers")
async def list_containers(user: str = Depends(verify_auth)):
    """List all manageable containers with their current limits and usage."""
    try:
        containers = await asyncio.to_thread(docker_mgr.list_manageable_containers)
    except Exception as e:
        logger.error("Failed to list containers: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to communicate with Docker Engine",
        )

    result = await asyncio.to_thread(docker_mgr.get_all_containers_info_parallel, containers)
    return {"containers": result}


# ── Get Container Detail ────────────────────────────────────────────────

@app.get("/api/v1/containers/{container_id}")
async def get_container(
    container_id: str,
    user: str = Depends(verify_auth),
):
    """Get detailed info for a specific manageable container."""
    container = await asyncio.to_thread(docker_mgr.get_container, container_id)
    if not container:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Container not found or not manageable (missing app.manageable=true label)",
        )

    try:
        info = await asyncio.to_thread(docker_mgr.get_container_info, container)
    except Exception as e:
        logger.error("Failed to get info for %s: %s", container_id, e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve container information",
        )

    return info


# ── Update Container Resources ──────────────────────────────────────────

@app.put("/api/v1/containers/{container_id}/resources")
async def update_resources(
    container_id: str,
    req: ResourceUpdateRequest,
    user: str = Depends(verify_auth),
):
    """
    Update CPU and/or RAM limits for a running container.

    Includes OOM safeguard: if the requested memory limit is below
    current actual usage and force=false, returns 409 Conflict.
    """
    # Find container
    container = await asyncio.to_thread(docker_mgr.get_container, container_id)
    if not container:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Container not found or not manageable (missing app.manageable=true label)",
        )

    # Must be running
    if container.status != "running":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Container is not running (current status: {container.status})",
        )

    # At least one value must be provided
    if req.memory_mb is None and req.cpu_cores is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one of memory_mb or cpu_cores must be provided",
        )

    # ── OOM Safeguard ───────────────────────────────────────────────────
    if req.memory_mb is not None and not req.force:
        stats = await asyncio.to_thread(docker_mgr.get_container_stats, container)
        current_usage_mb = stats["memory_usage_mb"]

        if req.memory_mb < current_usage_mb:
            logger.warning(
                "OOM Risk detected for %s: requested %s MB < usage %s MB",
                container.name,
                req.memory_mb,
                current_usage_mb,
            )
            return JSONResponse(
                status_code=status.HTTP_409_CONFLICT,
                content={
                    "error": "OOM_RISK_DETECTED",
                    "message": (
                        f"Požadovaný limit paměti ({req.memory_mb} MB) je nižší než "
                        f"aktuální využití ({current_usage_mb} MB). "
                        f"Snížení limitu pod aktuální využití může způsobit pád containeru (OOM Kill)."
                    ),
                    "current_usage_mb": current_usage_mb,
                    "requested_limit_mb": req.memory_mb,
                    "requires_confirmation": True,
                },
            )

    # ── Apply Resource Update & Compose Persistence ────────────────────
    try:
        compose_updated, compose_path = await asyncio.to_thread(
            docker_mgr.update_container_resources_and_compose,
            container=container,
            memory_mb=req.memory_mb,
            cpu_cores=req.cpu_cores,
        )
    except Exception as e:
        logger.error("Failed to update container %s: %s", container_id, e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to apply resource limits: {e}",
        )

    # Get updated limits
    new_limits = await asyncio.to_thread(docker_mgr.get_container_limits, container)

    logger.info(
        "Container %s (%s) resources updated: memory=%s MB, cpu=%s cores by %s (compose_updated=%s, file=%s)",
        container.name,
        container.short_id,
        new_limits.get("memory_limit_mb"),
        new_limits.get("cpu_limit_cores"),
        user,
        compose_updated,
        compose_path,
    )

    return {
        "success": True,
        "container_id": container.short_id,
        "applied_limits": {
            "memory_mb": new_limits["memory_limit_mb"],
            "cpu_cores": new_limits["cpu_limit_cores"],
        },
        "compose_file_updated": compose_updated,
        "compose_file_path": compose_path,
    }


# ── Favicon ─────────────────────────────────────────────────────────────

@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    """Serve the favicon."""
    return FileResponse("/app/static/favicon.svg", media_type="image/svg+xml")


# ── Serve Frontend ──────────────────────────────────────────────────────

app.mount("/static", StaticFiles(directory="/app/static"), name="static")


@app.get("/")
async def serve_frontend():
    """Serve the frontend SPA."""
    return FileResponse(
        "/app/static/index.html",
        headers={
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": (
                "default-src 'self'; "
                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                "font-src 'self' https://fonts.gstatic.com; "
                "script-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; "
                "connect-src 'self'; "
                "frame-ancestors 'none'; "
                "object-src 'none'"
            ),
        },
    )
