"""Tests for Kubernetes manifests structure and key configuration invariants.

These tests verify that the k8s/ manifests satisfy the architectural decisions
documented in ADR-0012 and ADR-0013 without running a live cluster.
"""

import yaml
import pytest
from pathlib import Path
from typing import Any

K8S_DIR = Path(__file__).parent.parent.parent / "k8s"

EXPECTED_MANIFESTS = [
    "namespace.yaml",
    "kafka/values.yaml",
    "elasticsearch/deployment.yaml",
    "elasticsearch/service.yaml",
    "prometheus/serviceaccount.yaml",
    "prometheus/role.yaml",
    "prometheus/rolebinding.yaml",
    "prometheus/configmap.yaml",
    "prometheus/deployment.yaml",
    "prometheus/service.yaml",
    "grafana/configmap-datasources.yaml",
    "grafana/configmap-dashboard-provider.yaml",
    "grafana/configmap-dashboards.yaml",
    "grafana/deployment.yaml",
    "grafana/service.yaml",
    "rule-engine/deployment.yaml",
    "rule-engine/service.yaml",
    "alert-storage/deployment.yaml",
    "log-generator/deployment.yaml",
    "log-generator/service.yaml",
]


def _load(rel_path: str) -> Any:
    return yaml.safe_load((K8S_DIR / rel_path).read_text())


def test_k8s_directory_exists() -> None:
    assert K8S_DIR.is_dir(), "k8s/ directory must exist (ADR-0013)"


@pytest.mark.parametrize("rel_path", EXPECTED_MANIFESTS)
def test_expected_manifest_exists(rel_path: str) -> None:
    assert (K8S_DIR / rel_path).exists(), f"Missing manifest: {rel_path}"


def test_rule_engine_deployment_replicas_equals_8() -> None:
    """Rule Engine must run 8 replicas to match the 8-partition raw-logs topic (ADR-0012)."""
    manifest = _load("rule-engine/deployment.yaml")
    assert manifest["spec"]["replicas"] == 8


def test_rule_engine_deployment_is_in_namespace() -> None:
    manifest = _load("rule-engine/deployment.yaml")
    assert manifest["metadata"]["namespace"] == "kafka-sigma-engine"


def test_prometheus_configmap_uses_kubernetes_sd_configs() -> None:
    """Prometheus must auto-discover rule-engine pods via kubernetes_sd_configs (ADR-0013)."""
    manifest = _load("prometheus/configmap.yaml")
    prom_config: dict[str, Any] = yaml.safe_load(manifest["data"]["prometheus.yml"])
    rule_engine_jobs = [
        j for j in prom_config["scrape_configs"] if j["job_name"] == "rule-engine"
    ]
    assert rule_engine_jobs, "rule-engine scrape job must exist in Prometheus config"
    job = rule_engine_jobs[0]
    assert "kubernetes_sd_configs" in job, (
        "rule-engine scrape job must use kubernetes_sd_configs, not static_configs (ADR-0013)"
    )


def test_kafka_values_provisions_raw_logs_with_8_partitions() -> None:
    """raw-logs topic must have 8 partitions for horizontal Rule Engine scaling (ADR-0012)."""
    values = _load("kafka/values.yaml")
    topics = values["provisioning"]["topics"]
    raw_logs = next((t for t in topics if t["name"] == "raw-logs"), None)
    assert raw_logs is not None, "raw-logs topic must be provisioned"
    assert raw_logs["partitions"] == 8


def test_log_generator_service_exposes_admin_port() -> None:
    """Log Generator admin HTTP endpoint must be reachable on port 8080 (ADR-0015)."""
    manifest = _load("log-generator/service.yaml")
    ports = manifest["spec"]["ports"]
    admin_port = next((p for p in ports if p["port"] == 8080), None)
    assert admin_port is not None, "Log Generator Service must expose port 8080 for admin HTTP"


def test_namespace_manifest_defines_kafka_sigma_engine() -> None:
    manifest = _load("namespace.yaml")
    assert manifest["kind"] == "Namespace"
    assert manifest["metadata"]["name"] == "kafka-sigma-engine"
