# warren-contract

The neutral client<->server contract shared by the Warren client SDK
(`warren-sdk-rs`) and the Warren backend (`warren-core`), so the wire contract
cannot drift between them. Warren is a privacy-focused VPN service:
<https://warrenbrowse.com>.

- `ss58`: the wallet-identity address codec (Warren prefix `13295`, `wb…`).
- `auth`: the X-Warren canonical signing message, the client-side signer, and
  the four `X-Warren-*` header-name constants.
- `dto`: the HTTP `/v1` API request/response types, plus the `redact()`
  no-log helper they use in error messages.
- `release`: the offline-signed exit-release manifest (the fleet update
  authority; doc 54).

The `warren-discovery` workspace member (crate `warren-discovery-core`)
carries the signed relay-list / roster / multi-hop directory formats and the
relay selector, consumed by `warren-core`'s `warren-relay-selector` and the
SDK's `warren-discovery`.

Every module has golden tests here, so the frozen behavior is pinned in one
place. `warren-core` re-exports these (`warren-api-types` from `dto` +
`release`, `warren-ss58` from `ss58`, `warren-identity::auth` from `auth`) and
the SDK does the same (`warren-api::dto`, `warren-identity::ss58`,
`warren-identity::signing`), so the contract has a single home and cannot
drift between client and backend.

Consumption: `warren-core` uses a sibling path-dep; `warren-sdk-rs` and
`warren-sdk-dart` pin a git rev (kept in `.warren-contract-version` there) and
`[patch]` it to the sibling for local dev. The WarrenGuard engine crates (for
`ExitId`) are pinned the same way here: `.warrenguard-version` must equal the
revs in `Cargo.toml` (CI enforces it). Design:
`warren-core/docs/49-PHASE5-CLIENT-CONVERGENCE.md`.

`warren-core` is the private Warren backend, so its doc paths and the `doc NN`
citations in source comments here resolve only for the Warren team. Everything
needed to build and test this crate is public.

## Build and test

```sh
cargo test --workspace
```

The `[patch]` at the foot of `Cargo.toml` redirects the pinned `warrenguard`
git dependencies to a sibling checkout at `../warrenguard` when one exists
(local dev and CI use it). A standalone clone needs no sibling: cargo resolves
the pinned git revs directly.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
