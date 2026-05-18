# EDR Parity — Linux Productisation

This document describes the build, loading, and runtime fallback
pipeline for the optional Linux eBPF programs shipped in Phase E6.4
of the EDR Parity workstream.

The eBPF programs are the *tamper-resistant* replacement for the
user-mode `cn_proc` + `audit` process / network backends introduced
in Phase E1. Agents that ship *without* eBPF support continue to
operate on `cn_proc` + `audit`; runtime detection picks the best
available transport automatically.

## High-level architecture

```
+---------------------------------+
|        Kernel mode              |
|                                 |
|  +---------------------------+  |
|  | sda_edr.bpf.o             |  |
|  |  kprobe sys_execve        |  |
|  |  kprobe tcp_v4_connect    |  |
|  |  kprobe udp_sendmsg       |  |
|  +-------------+-------------+  |
|                |  PerfRecord    |
|                v                |
|  BPF_MAP_TYPE_PERF_EVENT_ARRAY  |
+----------------|----------------+
                 |  perf ring
                 v
+---------------------------------+
|        User mode (agent)        |
|                                 |
|  Aya loader pins programs +     |
|  reads perf records.            |
|                                 |
|  sda_pal::kernel::linux_ebpf::  |
|    LinuxKernelChannel           |
|                                 |
|     -> ProcessMonitor stream    |
|     -> NetworkMonitor stream    |
+---------------------------------+
```

The on-the-wire layout is the
[`PerfRecord`](../../crates/sda-pal/src/kernel/linux_ebpf.rs) enum
serialised via `serde` (the kernel side emits a fixed-layout C
struct; the loader translates it into `PerfRecord` and then into the
generic `KernelEvent`). A user-mode parser
[`sda_pal::kernel::linux_ebpf::parse_perf_records`](../../crates/sda-pal/src/kernel/linux_ebpf.rs)
is exercised under CI against a mock perf ring.

## Toolchain requirements

| Component                  | Version              | Notes                |
|----------------------------|----------------------|----------------------|
| Linux kernel               | ≥ 5.8                | Required for `BPF_MAP_TYPE_RINGBUF` and `bpf_loop`; older kernels fall back to `cn_proc` automatically |
| `CAP_BPF` capability       | n/a                  | Required to load eBPF programs |
| `clang` + `llvm`           | ≥ 14                 | Compiles the eBPF object |
| Rust nightly + `aya`       | matching `Cargo.toml`| Builds the loader    |
| `bpftool` (optional)       | n/a                  | Diagnostics only     |

CI runners ship various kernel versions; some are too old for the
production path. The `kernel-linux-ebpf` Cargo feature is **off**
by default and gates the loader on
[`detect_ebpf_capability`](../../crates/sda-pal/src/kernel/linux_ebpf.rs).

## eBPF program scaffolding

The eBPF programs live in a sibling crate (intentionally not committed
yet because the Aya toolchain needs the host kernel's `vmlinux.h`):

1. `cargo new --lib --vcs none crates/sda-ebpf` (off-tree until
   E6.4 is fully landed).
2. Add `aya-ebpf` + `aya-log-ebpf` as no-std dependencies.
3. Author three programs:
   - `kprobe/sys_execve` → emits `PerfRecord::Exec`.
   - `kprobe/tcp_v4_connect` → emits `PerfRecord::Connect4` with
     `protocol = Tcp`.
   - `kprobe/udp_sendmsg` → emits `PerfRecord::Connect4` with
     `protocol = Udp`.
4. Each program writes a fixed-layout `#[repr(C)]` struct into the
   shared `BPF_MAP_TYPE_PERF_EVENT_ARRAY` map.
5. Build with `cargo xtask build-ebpf` (Aya pattern).

The fixed-layout struct is the binary on-wire shape; the user-mode
loader translates it into the JSON-shaped
[`PerfRecord`](../../crates/sda-pal/src/kernel/linux_ebpf.rs) before
handing to the rest of the agent.

## Runtime detection + fallback

At startup the supervisor calls
[`detect_ebpf_capability`](../../crates/sda-pal/src/kernel/linux_ebpf.rs):

```rust
if !sda_pal::kernel::linux_ebpf::detect_ebpf_capability() {
    // Fall back to cn_proc + audit (Phase E1).
    return start_user_mode_process_monitor();
}
match sda_pal::kernel::linux_ebpf::attach_to_perf_buffer() {
    Ok(channel) => start_kernel_mode_process_monitor(channel),
    Err(AttachError::NotPresent(_)) => start_user_mode_process_monitor(),
    Err(AttachError::Privilege(_)) => start_user_mode_process_monitor(),
    Err(AttachError::Io(e))      => bail!(e),
}
```

This contract is exercised under CI by the
`kernel_version_predicate_*` unit tests in `linux_ebpf.rs` and by the
mock channel.

## Packaging

The eBPF object (`sda_edr.bpf.o`) is packaged inside the agent
binary via `include_bytes!` so the agent has no runtime dependency on
the object file's location on disk. The loader pins the programs in
`/sys/fs/bpf/sn360/` at startup and unpins them on graceful shutdown.

A `/etc/systemd/system/sn360-desktop-agent.service` override adds the
required capabilities:

```ini
[Service]
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_NET_ADMIN
CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_NET_ADMIN
```

On distros without `CAP_BPF` (kernel < 5.8), the supervisor
gracefully falls back to `cn_proc` + `audit`.

## Failure mode handling

- **Kernel too old**: `detect_ebpf_capability` returns false →
  user-mode `cn_proc` + `audit` backends used.
- **`CAP_BPF` not granted**: Aya loader returns `EPERM` →
  `AttachError::Privilege` → fall back.
- **Verifier rejects program**: load fails →
  `AttachError::Io(EINVAL)` → fall back + log loudly so the build is
  fixed.
- **Schema drift**: per-record `serde_json::Error` (mock path) or
  `bytemuck::PodCastError` (production path) is logged and the
  record is dropped. The supervisor never panics on a malformed
  kernel record.

## Open questions / future work

- File-open tracepoints for FIM tamper-resistance can be added as a
  third program. Out of scope for E6.4.
- IPv6 connect tracking is a follow-up; the current scope is IPv4
  only (mirrors Phase E1 telemetry).
