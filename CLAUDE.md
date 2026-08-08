# warren-contract: rules for Claude Code

The **neutral client-to-server contract** shared by the private backend
(`warren-core`) and every client SDK. It owns the SS58 address codec, the
`X-Warren` canonical signing message plus its header names, the HTTP `/v1` DTOs,
and the signed discovery envelopes (`warren-discovery-core`, including the exit
roster and the operator notices).

It depends only on the `warrenguard` engine crates: `warrenguard-wire` in the
root crate, plus `warrenguard-multihop` in `warren-discovery-core`. That is the
whole point: both sides of the wire depend on this crate, so the contract cannot
drift between the SDK and the backend.

> Shared Warren rules (single source of truth: WarrenBrowse/warren-workspace).
> They resolve when this repo is checked out inside the workspace (mani sync);
> cloned standalone, the imports just warn harmlessly. Never restate one of them
> here: import it.
@../shared/rules/00-conventions.md
@../shared/rules/10-tdd.md
@../shared/rules/20-errors-secrets.md
@../shared/rules/30-git-commits.md
@../shared/rules/40-wire-vectors.md

## Prime directive: this crate IS the wire

Every type here is consumed by at least two independent implementations. A change
that compiles on both sides can still break the wire.

- **A DTO field, an enum variant, a header name and a signing-message layout are
  all frozen formats.** Adding a field is safe only if both sides tolerate the
  unknown; removing or renaming one is a `/v2`, never a mutation of `/v1`.
- **Every frozen format has a golden vector**, replayed by both the SDK and the
  backend, so a mismatch here breaks two implementations at once. The in-repo
  freeze tests live under `tests/` (`http_vectors.rs`, `phase_vectors.rs`,
  `fixtures/`); the cross-SDK corpus lives in the shared `warren-vectors` repo,
  submoduled as `vectors/` in `warrenguard`, `warren-core` and the SDK repos
  (the shared wire-vectors rule, imported above, governs what to do about a
  mismatch).
- **No product policy, no control-plane logic, no I/O.** This crate describes the
  contract; it does not decide anything. Anything that makes a decision belongs in
  `warren-core` (server side) or in the SDK (client side).
- **No dependency beyond the `warrenguard` engine crates and crates.io.** A
  path-dep into a consumer would invert the layering and break the standalone
  build that enforces it.

## Pin lockstep is gated in CI

This repo pins `warrenguard` twice, and the two must agree: the
`.warrenguard-version` file (which drives the sibling checkout in CI) and the
`rev = "..."` in `Cargo.toml`. The "pin lockstep" CI job fails when they diverge.

Advancing a pin has an order across five repos, and the `vectors` submodule is
checked FIRST. See the `warren-sibling-pins` skill.

## Signing and identity

The `auth` module builds the canonical `X-Warren` message that the client signs
and the server verifies. Both sides derive it from the same code, so a change here
is a simultaneous change to every client and to the backend.

- Never log or embed a full pubkey, an address or a nonce (shared no-log rule).
- The SS58 codec is checksummed and network-prefixed: a change to the prefix is an
  identity-format change, so it is a schema bump with new vectors, never a patch.
- **The canonical message carries no audience, so a PATH is a service
  reservation.** It is method, path, timestamp, nonce and body hash: no host, no
  service name. A signature is therefore valid at any Warren service that serves
  that path, and two services sharing one would make their signed requests
  interchangeable. Today `POST /v1/forum/*` belongs to warren-connect (the forum
  SSO broker) and warren-api serves only the unsigned `GET /v1/forum/digest`;
  keep it that way. Adding an audience field is the real fix and it is a `/v2`,
  because every deployed client signs the current layout.

## Verify before commit

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
