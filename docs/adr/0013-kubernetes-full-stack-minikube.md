# Full Kubernetes Stack in `k8s/` Using minikube

A separate `k8s/` directory contains manifests for the complete stack: Kafka (Bitnami Helm chart), Elasticsearch, Prometheus (with `kubernetes_sd_configs` for pod auto-discovery), Grafana, and all three microservices as Kubernetes Deployments. Docker Compose is retained as the fast local development environment; `k8s/` is the load-testing and portfolio-demo environment.

A hybrid approach (K8s for microservices only, Docker Compose for infrastructure) was rejected because Prometheus `kubernetes_sd_configs` requires Prometheus to run inside the cluster, and the full scaling story (`kubectl scale deployment rule-engine --replicas=8`) is only meaningful when Kafka is also inside the cluster.

minikube (Docker driver) is chosen over kind because:
- `minikube dashboard` provides a visual UI to demonstrate 8 Rule Engine pods running and scaling in real time — a meaningful portfolio artifact
- `minikube tunnel` makes LoadBalancer-type Services reachable from the host without `kubectl port-forward` juggling, simplifying the Grafana and Prometheus demo
- Single-node is sufficient for 8 Rule Engine pods
- kind would be preferred in a CI/CD context but the demo UX advantage of minikube outweighs its slightly higher resource cost for this project

## Consequences

- `k8s/` manifests must build and push images to minikube's internal Docker daemon (`eval $(minikube docker-env)`) or use `minikube image load`.
- The Rule Engine Deployment `spec.replicas` should be set to 8 (matching the 8-partition `raw-logs` topic from ADR-0012). Scaling below 8 is valid; Kafka redistributes partitions automatically. (ADR-0017: measured `requests`/`limits` usage showed 8 replicas leaves too little CPU headroom for Kafka on this 4-CPU target, so the shipped default is now 4; 8 is still reachable via `kubectl scale`.)
- Prometheus must be configured with `kubernetes_sd_configs` targeting the `rule-engine` pod label to auto-discover all replicas without static target lists.
