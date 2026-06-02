# Build From Source

Use this guide when developing AgentSight or building a local binary from the repository. If you only want to run a release binary, see the Quick Start in [README.md](../README.md).

## Requirements

- Linux with eBPF support
- Rust toolchain 1.88.0+
- Node.js 18+
- clang and LLVM
- libelf development headers
- zlib development headers
- make and standard C build tools

On Ubuntu/Debian, the repository Makefile can install the expected system dependencies:

```bash
make install
```

## Build

Clone with submodules:

```bash
git clone https://github.com/eunomia-bpf/agentsight.git --recursive
cd agentsight
```

If you already cloned without submodules:

```bash
git submodule update --init --recursive
```

Build all components:

```bash
make build
```

The built binary is at:

```text
collector/target/release/agentsight
```

Build individual components when iterating:

```bash
make build-frontend  # frontend assets
make build-bpf       # eBPF programs
make build-rust      # Rust collector
```

## Verify

Run the test suite:

```bash
make test
```

For frontend development:

```bash
cd frontend
npm run dev
```
