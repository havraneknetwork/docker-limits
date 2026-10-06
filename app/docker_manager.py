"""
Docker Manager - handles all communication with Docker Engine API.
Manages container resource limits via cgroups without restart.
"""

import concurrent.futures
import logging
from typing import Optional, List, Dict, Any

import docker
import docker.errors

from .config import MANAGEABLE_LABEL, MANAGEABLE_LABEL_VALUE
from .compose_sync import sync_compose_limits, get_compose_info_from_container

logger = logging.getLogger("limits")


class DockerManager:
    """Manages Docker container resource operations."""

    def __init__(self) -> None:
        """Initialize Docker client from environment (socket)."""
        try:
            self.client = docker.from_env()
            info = self.client.info()
            logger.info(
                "Connected to Docker Engine: %s (API %s)",
                info.get("ServerVersion", "unknown"),
                self.client.api.api_version,
            )
        except docker.errors.DockerException as e:
            logger.error("Failed to connect to Docker Engine: %s", e)
            raise

    def list_manageable_containers(self) -> list:
        """
        List all manageable containers:
        1. Containers with app.manageable=true label
        2. All existing running/stopped containers, unless app.manageable=false
        """
        try:
            all_containers = self.client.containers.list(all=True)
            manageable = []
            for c in all_containers:
                lbl = (c.labels or {}).get(MANAGEABLE_LABEL)
                # If explicit false, skip. If true or not specified, manage it
                if lbl != "false":
                    manageable.append(c)

            logger.info("Found %d manageable container(s) out of %d", len(manageable), len(all_containers))
            return manageable
        except docker.errors.APIError as e:
            logger.error("Docker API error listing containers: %s", e)
            raise

    def get_container(self, container_id: str) -> Optional[docker.models.containers.Container]:
        """
        Get a specific container by ID or name.
        Returns None if not found or explicitly excluded (app.manageable=false).
        """
        try:
            container = self.client.containers.get(container_id)
        except docker.errors.NotFound:
            logger.warning("Container not found: %s", container_id)
            return None
        except docker.errors.APIError as e:
            logger.error("Docker API error getting container %s: %s", container_id, e)
            return None

        # Verify not explicitly disabled
        labels = container.labels or {}
        if labels.get(MANAGEABLE_LABEL) == "false":
            logger.warning("Container %s is explicitly excluded (app.manageable=false)", container_id)
            return None

        return container

    def get_container_stats(self, container: docker.models.containers.Container) -> dict:
        """
        Get current resource usage statistics for a running container.
        Memory usage = usage - cache (handles both cgroup v1 and v2).
        """
        if container.status != "running":
            return {"memory_usage_mb": 0.0, "cpu_percent": 0.0}

        try:
            stats = container.stats(stream=False)
        except docker.errors.APIError as e:
            logger.error(
                "Failed to get stats for container %s: %s", container.name, e
            )
            return {"memory_usage_mb": 0.0, "cpu_percent": 0.0}

        # --- Memory calculation ---
        mem_stats = stats.get("memory_stats", {})
        usage = mem_stats.get("usage", 0)

        # cgroup v2 uses inactive_file, cgroup v1 uses cache
        cache = 0
        inner_stats = mem_stats.get("stats", {})
        if "inactive_file" in inner_stats:
            cache = inner_stats["inactive_file"]
        elif "cache" in inner_stats:
            cache = inner_stats["cache"]

        actual_usage = max(0, usage - cache)
        memory_usage_mb = round(actual_usage / (1024 * 1024), 2)

        # --- CPU calculation ---
        cpu_percent = 0.0
        try:
            cpu_stats = stats.get("cpu_stats", {})
            precpu_stats = stats.get("precpu_stats", {})

            cpu_total = cpu_stats.get("cpu_usage", {}).get("total_usage", 0)
            precpu_total = precpu_stats.get("cpu_usage", {}).get("total_usage", 0)
            cpu_delta = cpu_total - precpu_total

            system_total = cpu_stats.get("system_cpu_usage", 0)
            presystem_total = precpu_stats.get("system_cpu_usage", 0)
            system_delta = system_total - presystem_total

            num_cpus = cpu_stats.get("online_cpus", 1)

            if system_delta > 0 and cpu_delta >= 0:
                cpu_percent = round(
                    (cpu_delta / system_delta) * num_cpus * 100.0, 2
                )
        except (KeyError, TypeError, ZeroDivisionError):
            cpu_percent = 0.0

        return {
            "memory_usage_mb": memory_usage_mb,
            "cpu_percent": cpu_percent,
        }

    def get_container_limits(self, container: docker.models.containers.Container) -> dict:
        """Get current resource limits from container's HostConfig."""
        container.reload()
        attrs = container.attrs
        host_config = attrs.get("HostConfig", {})

        # Memory limit (0 = unlimited)
        memory_limit = host_config.get("Memory", 0)
        memory_limit_mb = (
            round(memory_limit / (1024 * 1024), 2) if memory_limit else None
        )

        # CPU limit via NanoCPUs (0 = unlimited) or CpuQuota / CpuPeriod
        nano_cpus = host_config.get("NanoCpus", 0)
        cpu_quota = host_config.get("CpuQuota", 0)
        cpu_period = host_config.get("CpuPeriod", 100000) or 100000

        if nano_cpus:
            cpu_limit_cores = round(nano_cpus / 1e9, 2)
        elif cpu_quota and cpu_quota > 0:
            cpu_limit_cores = round(cpu_quota / cpu_period, 2)
        else:
            cpu_limit_cores = None

        return {
            "memory_limit_mb": memory_limit_mb,
            "cpu_limit_cores": cpu_limit_cores,
        }

    def get_container_info(
        self,
        container: docker.models.containers.Container,
        include_stats: bool = True,
    ) -> dict:
        """Build a complete info dict for a container."""
        # Image tag
        image_name = "unknown"
        try:
            if container.image.tags:
                image_name = container.image.tags[0]
            else:
                image_name = container.image.short_id
        except Exception:
            image_name = "unknown"

        info = {
            "id": container.short_id,
            "name": container.name,
            "status": container.status,
            "image": image_name,
        }

        # Compose metadata
        compose_info = get_compose_info_from_container(container)
        if compose_info:
            info["is_compose"] = True
            info["compose_file"] = compose_info[0]
            info["compose_service"] = compose_info[1]
        else:
            info["is_compose"] = False
            info["compose_file"] = None
            info["compose_service"] = None

        # Limits
        limits = self.get_container_limits(container)
        info.update(limits)

        # Usage stats (only for running containers)
        if include_stats and container.status == "running":
            stats = self.get_container_stats(container)
            info["memory_usage_mb"] = stats["memory_usage_mb"]
            info["cpu_usage_percent"] = stats["cpu_percent"]
        else:
            info["memory_usage_mb"] = 0.0
            info["cpu_usage_percent"] = 0.0

        return info

    def get_all_containers_info_parallel(self, containers: list) -> list:
        """Fetch container information in parallel using a thread pool for fast response."""
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            future_to_c = {executor.submit(self.get_container_info, c, True): c for c in containers}
            for future in concurrent.futures.as_completed(future_to_c):
                c = future_to_c[future]
                try:
                    info = future.result()
                    results.append(info)
                except Exception as e:
                    logger.error("Failed to get info for container %s: %s", c.name, e)
                    try:
                        # Fallback without live stats
                        results.append(self.get_container_info(c, include_stats=False))
                    except Exception:
                        pass
        # Sort by container name for consistent UI display
        results.sort(key=lambda x: x["name"])
        return results

    def update_container_resources(
        self,
        container: docker.models.containers.Container,
        memory_mb: Optional[int] = None,
        cpu_cores: Optional[float] = None,
    ) -> None:
        """
        Update container resource limits using Docker's update API.
        This modifies cgroups directly without restarting the container.
        """
        payload = {}

        if memory_mb is not None:
            mem_bytes = memory_mb * 1024 * 1024
            payload["Memory"] = mem_bytes
            payload["MemorySwap"] = mem_bytes

        if cpu_cores is not None:
            # NanoCPUs is required when containers were created with cpus in compose (avoids Conflict error)
            payload["NanoCPUs"] = int(cpu_cores * 1e9)

        logger.info(
            "Updating container %s (%s) resources: %s",
            container.name,
            container.short_id,
            payload,
        )

        try:
            url = self.client.api._url("/containers/{0}/update", container.id)
            res = self.client.api._post_json(url, data=payload)
            if res.status_code >= 400:
                raise docker.errors.APIError(f"Update failed with status {res.status_code}: {res.text}")
            container.reload()
            logger.info("Successfully updated container %s", container.name)
        except Exception as e:
            logger.error(
                "Failed to update container %s: %s", container.name, e
            )
            raise

    def update_container_resources_and_compose(
        self,
        container: docker.models.containers.Container,
        memory_mb: Optional[int] = None,
        cpu_cores: Optional[float] = None,
    ) -> tuple[bool, Optional[str]]:
        """
        Update container runtime resources via Docker API AND persist changes
        to the container's docker-compose.yml file on disk.
        Returns (compose_updated_bool, compose_file_path).
        """
        # 1. Update runtime cgroups
        self.update_container_resources(
            container=container,
            memory_mb=memory_mb,
            cpu_cores=cpu_cores,
        )

        # 2. Persist to docker-compose.yml
        compose_updated, compose_path = sync_compose_limits(
            container=container,
            memory_mb=memory_mb,
            cpu_cores=cpu_cores,
        )

        return compose_updated, compose_path
