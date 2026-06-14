# cnode validation

The regular validation surface is the build plus CTest structural gates:

```powershell
cmake --build build --config Release
ctest --test-dir build --output-on-failure
```

Current expected local gate count:

```text
141/141 tests passed
```

## Gate Groups

The CMake tests under `tests/` are source-structure gates. They are intentionally
kept after the migration because they define the final architecture contract:

- request path, dispatcher, router, and relay boundaries
- protocol-private helper placement
- Buffer and MultiBuffer ownership
- runtime snapshot and config cold-path normalization
- public API dependency boundaries
- panel/control-plane isolation from traffic hot paths
- deployment configuration layout
- AnyTLS wire/config semantics

These gates can be consolidated by domain later, but they should not be removed
without an equivalent broader gate replacing them.

## External Traffic Evidence

The one-off local and VPS protocol traffic scripts have been removed from the
repository. The last recorded matrix before removal was:

- local cnode inbound/outbound against xray-core AnyTLS PR build, mihomo, and
  sing-box: 24/24
- VPS cnode inbound against local xray-core AnyTLS PR build, mihomo, and
  sing-box clients: 12/12
- VPS cnode outbound against local xray-core AnyTLS PR build, mihomo, and
  sing-box servers: 12/12
- config matrix: 17/17

Historical details are kept in `docs/archive/xray-core-xrayr-alignment.md`.
