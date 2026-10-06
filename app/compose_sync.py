"""
Compose File Synchronization Module.

Persists container resource limits (mem_limit, cpus) into docker-compose.yml
files on disk so that settings persist across container recreations and restarts.
"""

import os
import re
import logging
from typing import Optional, Tuple
import yaml

from .config import ALLOWED_HOST_ROOT

logger = logging.getLogger("limits")


def get_compose_info_from_container(container) -> Optional[Tuple[str, str]]:
    """
    Extract compose file path and service name from container Docker labels.
    Returns (compose_file_path, service_name) or None if container is not Compose-managed.
    """
    labels = container.labels or {}
    config_files = labels.get("com.docker.compose.project.config_files")
    service_name = labels.get("com.docker.compose.service")

    if not config_files or not service_name:
        return None

    # config_files can be comma-separated list of compose files; use the first one
    file_path = config_files.split(",")[0].strip()
    return file_path, service_name


def update_compose_service_limits(
    yaml_text: str,
    service_name: str,
    memory_mb: Optional[int] = None,
    cpu_cores: Optional[float] = None,
) -> str:
    """
    Update or insert mem_limit and cpus under the specified service in a compose YAML string,
    preserving comments, other services, and formatting.
    """
    lines = yaml_text.splitlines(keepends=True)
    in_services = False
    in_target_service = False
    target_service_indent = None

    mem_line_idx = None
    cpus_line_idx = None
    last_service_prop_idx = None
    prop_indent = None

    for i, line in enumerate(lines):
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())

        if stripped == "services:" and indent == 0:
            in_services = True
            continue

        if in_services:
            # Top-level section boundary
            if indent == 0 and stripped and not stripped.startswith("#"):
                in_services = False
                in_target_service = False
                continue

            if not in_target_service:
                match = re.match(r"^(\s*)" + re.escape(service_name) + r":\s*(?:#.*)?$", line)
                if match:
                    in_target_service = True
                    target_service_indent = len(match.group(1))
                    continue
            else:
                # If we encounter an entry at or shallower than target service indentation, we left the service
                if indent <= target_service_indent and stripped and not stripped.startswith("#"):
                    break

                if stripped and not stripped.startswith("#"):
                    last_service_prop_idx = i
                    if prop_indent is None and indent > target_service_indent:
                        prop_indent = " " * indent

                    if re.match(r"^\s*mem_limit:\s*.*$", line):
                        mem_line_idx = i
                    elif re.match(r"^\s*cpus:\s*.*$", line):
                        cpus_line_idx = i

    if not in_target_service and target_service_indent is None:
        raise ValueError(f"Service '{service_name}' not found under 'services:' in compose file")

    if prop_indent is None:
        prop_indent = " " * ((target_service_indent or 2) + 2)

    new_lines = list(lines)

    # 1. Memory limit
    if memory_mb is not None:
        mem_str = f"{memory_mb}m"
        if mem_line_idx is not None:
            new_lines[mem_line_idx] = f"{prop_indent}mem_limit: {mem_str}\n"
        else:
            insert_pos = (last_service_prop_idx + 1) if last_service_prop_idx is not None else len(new_lines)
            new_lines.insert(insert_pos, f"{prop_indent}mem_limit: {mem_str}\n")
            if cpus_line_idx is not None and cpus_line_idx >= insert_pos:
                cpus_line_idx += 1
            last_service_prop_idx = insert_pos

    # 2. CPU cores
    if cpu_cores is not None:
        cpus_formatted = f"{cpu_cores:g}"
        if cpus_line_idx is not None:
            new_lines[cpus_line_idx] = f"{prop_indent}cpus: {cpus_formatted}\n"
        else:
            insert_pos = (last_service_prop_idx + 1) if last_service_prop_idx is not None else len(new_lines)
            new_lines.insert(insert_pos, f"{prop_indent}cpus: {cpus_formatted}\n")
            last_service_prop_idx = insert_pos

    result = "".join(new_lines)

    # Validate output with YAML parser to guarantee valid syntax
    parsed = yaml.safe_load(result)
    if not isinstance(parsed, dict) or "services" not in parsed or service_name not in parsed["services"]:
        raise ValueError("Failed to validate updated YAML structure")

    return result


def sync_compose_limits(
    container,
    memory_mb: Optional[int] = None,
    cpu_cores: Optional[float] = None,
) -> Tuple[bool, Optional[str]]:
    """
    Locates container compose file on host, updates limits and saves safely.
    Returns (success_bool, compose_file_path).
    """
    info = get_compose_info_from_container(container)
    if not info:
        logger.info("Container %s is not managed by Docker Compose", container.name)
        return False, None

    file_path, service_name = info

    # Security: Path validation & sandbox boundary check
    resolved = os.path.realpath(file_path)
    allowed_root = os.path.realpath(ALLOWED_HOST_ROOT)
    if not (resolved == allowed_root or resolved.startswith(allowed_root + os.sep)):
        logger.warning(
            "Compose file %s is outside allowed boundary %s for container %s",
            resolved,
            allowed_root,
            container.name,
        )
        return False, resolved

    if not (resolved.endswith(".yml") or resolved.endswith(".yaml")):
        logger.warning("Target file %s is not a YAML file", resolved)
        return False, resolved

    if not os.path.isfile(resolved):
        logger.warning("Compose file %s does not exist on disk", resolved)
        return False, resolved

    try:
        with open(resolved, "r", encoding="utf-8") as f:
            content = f.read()

        updated_yaml = update_compose_service_limits(
            yaml_text=content,
            service_name=service_name,
            memory_mb=memory_mb,
            cpu_cores=cpu_cores,
        )

        # Atomic file write preserving stat permissions and ownership
        st = os.stat(resolved)
        temp_path = f"{resolved}.tmp.{os.getpid()}"

        with open(temp_path, "w", encoding="utf-8") as f:
            f.write(updated_yaml)

        os.chmod(temp_path, st.st_mode)
        try:
            os.chown(temp_path, st.st_uid, st.st_gid)
        except PermissionError:
            pass

        os.replace(temp_path, resolved)
        logger.info(
            "Successfully synced limits to compose file %s (service: %s, mem: %s, cpu: %s)",
            resolved,
            service_name,
            memory_mb,
            cpu_cores,
        )
        return True, resolved

    except Exception as e:
        logger.error("Failed to sync compose limits for %s: %s", container.name, e)
        # Clean up temp file if present
        temp_path = f"{resolved}.tmp.{os.getpid()}"
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass
        return False, resolved
