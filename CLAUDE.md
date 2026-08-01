# warren-contract: rules for Claude Code

The **neutral client-to-server contract** shared by the private backend
(`warren-core`) and every client SDK. It owns the SS58 address codec, the
`X-Warren` canonical signing message plus its header names, the HTTP `/v1` DTOs,
and the signed discovery envelopes (`warren-discovery`, including the exit roster
and the operator notices).

It depends only on `warrenguard-wire`. That is the whole point: both sides of the
wire depend on this crate, so the contract cannot drift between the SDK and the
backend.

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
- **Every frozen format has a golden vector** under `vectors/` and is replayed by
  the SDK and by the backend. Never edit a vector to make a test pass. See the
  shared wire-vectors rule.
- **No product policy, no control-plane logic, no I/O.** This crate describes the
  contract; it does not decide anything. Anything that makes a decision belongs in
  `warren-core` (server side) or in the SDK (client side).
- **No dependency beyond `warrenguard-wire` and crates.io.** A path-dep into a
  consumer would invert the layering and break the standalone build that enforces
  it.

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

## Verify before commit

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
