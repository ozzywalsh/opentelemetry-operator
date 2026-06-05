# ClusterOBIAgent & OBIInstrumentation: Example Usage

## ClusterOBIAgent Examples

### Minimal: Application tracing with defaults

```yaml
apiVersion: opentelemetry.io/v1alpha1
kind: ClusterOBIAgent
metadata:
  name: default
spec:
  config: |
    otel_traces_export:
      endpoint: http://otel-collector.observability:4318
```

Deploys OBI in `application` mode (HTTP/gRPC uprobe tracing) across all nodes. Uses the operator's bundled image and default capabilities.

### Network observability only

```yaml
apiVersion: opentelemetry.io/v1alpha1
kind: ClusterOBIAgent
metadata:
  name: network-monitor
spec:
  mode: network
  nodeSelector:
    node-role.kubernetes.io/worker: ""
  config: |
    otel_metrics_export:
      endpoint: http://otel-collector.observability:4318
    network:
      cidrs:
        - 10.0.0.0/8
```

Provisions `NET_ADMIN` instead of application-tracing capabilities. Targets worker nodes only.

### Full mode on EKS/AKS (SYS_ADMIN required)

```yaml
apiVersion: opentelemetry.io/v1alpha1
kind: ClusterOBIAgent
metadata:
  name: eks-full
spec:
  mode: full
  image: ghcr.io/grafana/beyla:v2.2.0
  additionalCapabilities:
    - SYS_ADMIN
  resources:
    requests:
      cpu: 100m
      memory: 256Mi
    limits:
      memory: 512Mi
  config: |
    otel_traces_export:
      endpoint: http://otel-collector.observability:4318
    otel_metrics_export:
      endpoint: http://otel-collector.observability:4318
```

`SYS_ADMIN` is needed on managed clusters where `kernel.perf_event_paranoid > 1`. Also required for Go distributed tracing context propagation.

### Multi-nodepool deployment

```yaml
apiVersion: opentelemetry.io/v1alpha1
kind: ClusterOBIAgent
metadata:
  name: gpu-pool
spec:
  mode: application
  nodeSelector:
    accelerator: nvidia-tesla-t4
  tolerations:
    - key: nvidia.com/gpu
      operator: Exists
      effect: NoSchedule
  config: |
    otel_traces_export:
      endpoint: http://otel-collector.observability:4318
---
apiVersion: opentelemetry.io/v1alpha1
kind: ClusterOBIAgent
metadata:
  name: general-pool
spec:
  mode: full
  nodeSelector:
    workload-type: general
  config: |
    otel_traces_export:
      endpoint: http://otel-collector.observability:4318
    otel_metrics_export:
      endpoint: http://otel-collector.observability:4318
```

Two separate agents targeting different node pools with different modes and capabilities.

### Tenant delegation with allow-list

```yaml
apiVersion: opentelemetry.io/v1alpha1
kind: ClusterOBIAgent
metadata:
  name: production
spec:
  mode: application
  tenantDelegation:
    mode: AllowList
    namespacesAllowList:
      - team-payments
      - team-inventory
      - team-frontend
  config: |
    otel_traces_export:
      endpoint: http://otel-collector.observability:4318
```

Only the three listed namespaces can create `OBIInstrumentation` resources. All others are ignored.

### Tenant delegation: open collection

```yaml
apiVersion: opentelemetry.io/v1alpha1
kind: ClusterOBIAgent
metadata:
  name: dev-cluster
spec:
  mode: application
  tenantDelegation:
    mode: AlwaysCollect
  config: |
    otel_traces_export:
      endpoint: http://otel-collector.observability:4318
```

Any namespace can opt in. Suitable for development clusters where all tenants are trusted.

---

## OBIInstrumentation Examples

### Instrument all opted-in pods in a namespace

```yaml
apiVersion: opentelemetry.io/v1alpha1
kind: OBIInstrumentation
metadata:
  name: default
  namespace: team-payments
spec:
  podAnnotations:
    instrument-with-obi: "true"
```

Instruments any pod in `team-payments` that carries the annotation `instrument-with-obi: "true"`. The controller injects `k8s_namespace: team-payments` — pods in other namespaces are never matched.

A deployment opting in:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: checkout-service
  namespace: team-payments
spec:
  template:
    metadata:
      annotations:
        instrument-with-obi: "true"    # matches the OBIInstrumentation selector
    spec:
      containers:
        - name: checkout
          image: my-registry.example.com/checkout:v3.1.0
```

### Narrow targeting: specific service tier

```yaml
apiVersion: opentelemetry.io/v1alpha1
kind: OBIInstrumentation
metadata:
  name: critical-services
  namespace: team-inventory
spec:
  podAnnotations:
    instrument-with-obi: "true"
    service-tier: critical
```

Multiple annotations are AND'd — only pods with **both** annotations are instrumented. This lets teams progressively roll out tracing to high-value services first.

### Multiple OBIInstrumentation resources in one namespace

```yaml
apiVersion: opentelemetry.io/v1alpha1
kind: OBIInstrumentation
metadata:
  name: api-services
  namespace: team-frontend
spec:
  podAnnotations:
    obi-group: api
---
apiVersion: opentelemetry.io/v1alpha1
kind: OBIInstrumentation
metadata:
  name: background-workers
  namespace: team-frontend
spec:
  podAnnotations:
    obi-group: workers
```

Each resource becomes a separate discovery filter item. A pod matches if it satisfies **all** annotations in **any one** item — the items themselves are OR'd.

---

## Resulting ConfigMap (compiled by the controller)

Given the `OBIInstrumentation` resources above, the controller compiles the following discovery section into the agent ConfigMap:

```yaml
discovery:
  instrument:
    - k8s_namespace: team-payments
      k8s_pod_annotations:
        instrument-with-obi: "true"
    - k8s_namespace: team-inventory
      k8s_pod_annotations:
        instrument-with-obi: "true"
        service-tier: critical
    - k8s_namespace: team-frontend
      k8s_pod_annotations:
        obi-group: api
    - k8s_namespace: team-frontend
      k8s_pod_annotations:
        obi-group: workers
```

Each entry's `k8s_namespace` is injected by the controller and cannot be overridden by tenants.
