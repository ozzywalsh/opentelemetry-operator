# OBI Compatibility Research: Operator ↔ eBPF Instrumentation

Summary of findings on how the OpenTelemetry Operator should manage compatibility with
OpenTelemetry eBPF Instrumentation (OBI) for the ClusterOBIAgent controller RFC.

## 1. OBI Versioning Status

OBI is **pre-v1 / Development** status. All user-facing surfaces are explicitly unstable:
config schema, CLI flags, env vars, emitted telemetry, and the support matrix.

- **Current version:** `v0.9.0` (single Go module, single release line)
- **No dual versioning** like the collector (`v1.x/v0.x`). One `v0.x.y` tag covers everything.
- Minor releases may include breaking changes to any surface.
- Users are told to pin semver tags and review release notes before upgrading.

**Source:** [`VERSIONING.md`](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/VERSIONING.md)

## 2. Recommended Compatibility Strategy: Pin-Per-Release

The operator should **pin a single tested OBI version per operator release** as the default
image. Users can override via `spec.image`, but the operator makes no guarantees for untested
versions.

| Operator Release | Bundled OBI Version | Notes |
|---|---|---|
| v0.153.0 | v0.9.0 | Initial ClusterOBIAgent release |
| v0.154.0+ | v0.10.0+ | Bumped after testing |

**Why a min-version floor (e.g. "v0.9.0+") is not viable:**

The operator is not fully opaque to OBI's config. The compilation loop (design doc §7.3)
generates the `discovery.instrument` section — a typed integration point. If OBI changes this
schema in a minor release (which it can, pre-v1), the operator silently produces config OBI
ignores, breaking namespace isolation with no error.

A min-version floor becomes viable **after OBI reaches v1**, when the config schema is covered
by backwards-compatibility guarantees.

## 3. Config v2 Redesign (In Progress)

OBI has an active config v2.0 redesign that will break the operator's current config generation
path. This is the strongest argument for pin-per-release.

**Status:** Draft for discussion (design finalized, implementation phased)

**Source:** [`devdocs/config/version-2.0/config-v2.md`](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/devdocs/config/version-2.0/config-v2.md)

### 3.1 Discovery Config Breaking Change

The v1 discovery config the operator currently generates:

```yaml
discovery:
  instrument:
    - k8s_namespace: "default"
      k8s_pod_annotations:
        obi.instrument: "true"
```

Becomes in v2:

```yaml
extensions:
  obi:
    capture:
      rules:
        - action: include
          match:
            kubernetes:
              namespace_glob: ["default"]
              pod_annotations:
                obi.instrument: "true"
```

Completely different structure, path, and field names.

### 3.2 v2 Config Structure

The v2 config uses the OTel declarative configuration format with OBI-specific config under
`extensions.obi`. This block is divided by deployment scope:

| Section | Scope | Purpose |
|---|---|---|
| `capture` | All deployment modes (standalone + receiver) | Workload selection, protocol instrumentation, limits, eBPF engine |
| `enrich` | Standalone only | Kubernetes metadata enrichment, service naming |
| `correlation` | Standalone only | Log trace annotation, context correlation |
| `daemon` | Standalone only | Logging, profiling, shutdown, internal metrics |

In collector/receiver mode, only `capture` is valid. The collector pipeline handles enrichment
(via `k8sattributesprocessor`) and process lifecycle.

### 3.3 Receiver vs. Extension Clarification

`extensions.obi` is the OBI **config file** namespace — not an OTel Collector extension
component. In collector mode:

- `extensions.obi.capture` is the block that gets embedded into the receiver config
- The collector config references `receivers: [obi]` in its pipeline
- The receiver internally consumes the `capture` block
- `enrich`, `correlation`, `daemon` are rejected in receiver context

### 3.4 v2 Rules Structure

The new `capture.rules` uses an ordered rule list with typed match selectors
(similar to PrometheusRule or NetworkPolicy):

```yaml
capture:
  policy:
    default_action: include
    match_order: first_match_wins
  rules:
    - action: exclude
      name: exclude-system-namespaces
      match:
        kubernetes:
          namespace_glob: [kube-system, cert-manager, monitoring]
    - action: include
      name: tenant-alpha
      match:
        kubernetes:
          namespace_glob: ["tenant-alpha"]
          pod_annotations:
            obi.instrument: "true"
      refine:
        exports:
          traces: true
          metrics: false
```

Match dimensions: `kubernetes` (namespace_glob, pod_annotations), `process` (exe_path_glob,
exports_otlp). Include rules support an optional `refine` block for per-workload overrides
(signal selection, HTTP routes, filters).

### 3.5 v1 Deprecation Already In Progress

The v1 config surface is already shifting. In current code (`pkg/appolly/discover/matcher.go`),
`discovery.services` is deprecated in favor of `discovery.instrument` with log warnings.

### 3.6 Migration Rollout Plan

| Phase | Description |
|---|---|
| Phase 0 | Build v2 parser, migration CLI, validation CLI, `obi_rule_based` sampler plugin |
| Phase 1 | Freeze v1 key surface except critical fixes |
| Phase 2 | Dual-read period (v2 parser first, fallback to v1) |
| Phase 3 | v2-first default, v1 deprecated with warnings |
| Phase 4 | v1 retirement, remove v1 parsing entirely |

**Source:** [`devdocs/config/version-2.0/migration.md`](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/devdocs/config/version-2.0/migration.md)

## 4. Impact on OBIInstrumentation CRD

The current `OBIInstrumentationSpec` with only `PodAnnotations` is **forward-compatible with v2**.
The CRD is the operator's abstraction — it does not need to mirror OBI's config structure.

When OBI moves to v2, only the operator's internal config generation changes. Tenants continue
creating the same `OBIInstrumentation` resources. The operator translates intent into the
appropriate config shape based on the pinned OBI version.

**Future extensibility:** The v2 rules structure opens a path for richer `OBIInstrumentation`
fields (process matching, signal selection via `refine`) as additive, non-breaking CRD changes.
The namespace isolation guarantee holds regardless — the operator always injects `namespace_glob`
from the CR's namespace.

The CRD should remain **intent-based** ("instrument my stuff") rather than mechanism-based
("here are my OBI rules"). Exposing `action: include | exclude` and `match` fields is possible
with the operator still injecting namespace, but is better deferred until v2 is stable and real
user feedback exists.

## 5. OBI Support Matrix

For reference, OBI's current runtime requirements:

| Requirement | Supported |
|---|---|
| Kernel | Linux 5.8+ (4.18+ for RHEL-based with eBPF backports) |
| BTF | Required |
| CPU | amd64, arm64 |
| Privileges | Root or required Linux capabilities |

Protocol instrumentation covers HTTP 1.0/1.1/2.0, gRPC, MySQL, PostgreSQL, MSSQL, Redis,
MongoDB, Kafka, MQTT, AMQP, GraphQL, Elasticsearch, AWS S3/SQS, and GenAI providers.
Go library-level instrumentation covers net/http, grpc, gorilla/mux, gin, database/sql,
and several database/messaging drivers.

**Source:** [`SUPPORT_MATRIX.md`](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/SUPPORT_MATRIX.md)

## 6. Upstream References

- [OTel declarative config: extensions placement discussion](https://github.com/open-telemetry/opentelemetry-configuration/issues/335)
- [OBI comment with context on extensions.obi placement](https://github.com/open-telemetry/opentelemetry-configuration/issues/335#issuecomment-3954773010)
- [OTel declarative config: ownership/overlap follow-up](https://github.com/open-telemetry/opentelemetry-configuration/issues/545)
- [OBI VERSIONING.md](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/VERSIONING.md)
- [OBI SUPPORT_MATRIX.md](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/SUPPORT_MATRIX.md)
- [OBI config v2 design](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/devdocs/config/version-2.0/config-v2.md)
- [OBI config v2 migration plan](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/devdocs/config/version-2.0/migration.md)
- [OBI config v2 JSON schema](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/devdocs/config/version-2.0/obi-extension.schema.json)
- [OTel Operator compatibility matrix](https://github.com/open-telemetry/opentelemetry-operator/blob/main/docs/compatibility.md)
