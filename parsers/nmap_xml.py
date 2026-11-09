from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from core.logger import get_logger

logger = get_logger(__name__)


def parse(raw_path: Path) -> list[dict]:
    """Parse Nmap XML output into a list of host records with open-port metadata."""
    if not raw_path.exists():
        return []

    try:
        tree = ET.parse(raw_path)
    except ET.ParseError as exc:  # pragma: no cover - resilient parser path
        logger.warning("Failed to parse Nmap XML at %s: %s", raw_path, exc)
        return []

    root = tree.getroot()
    results: list[dict] = []
    for host_node in root.findall(".//host"):
        addr_nodes = host_node.findall("address")
        ip_value = ""
        for addr_node in addr_nodes:
            addr_type = (addr_node.get("addrtype") or "").lower()
            if addr_type in {"ipv4", "ipv6"}:
                ip_value = str(addr_node.get("addr") or "").strip()
                if ip_value:
                    break

        if not ip_value:
            continue

        ports: list[dict] = []
        for port_node in host_node.findall("./ports/port"):
            state_node = port_node.find("state")
            if state_node is None or (state_node.get("state") or "").lower() != "open":
                continue

            port_id = str(port_node.get("portid") or "").strip()
            protocol = str(port_node.get("protocol") or "").strip()
            if not port_id:
                continue

            service_node = port_node.find("service")
            service_name = (service_node.get("name") if service_node is not None else "") or ""
            product = (service_node.get("product") if service_node is not None else "") or ""
            version = (service_node.get("version") if service_node is not None else "") or ""
            ports.append(
                {
                    "port": int(port_id),
                    "protocol": protocol,
                    "service": service_name,
                    "product": product,
                    "version": version,
                }
            )

        results.append({"ip": ip_value, "ports": ports})

    return results
