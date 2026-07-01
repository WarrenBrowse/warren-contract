# warren-contract

The neutral client<->server contract shared by the Warren client SDK
(`warren-sdk-rs`) and the Warren backend (`warren-core`), so the wire contract
cannot drift between them.

- `ss58`: the wallet-identity address codec (Warren prefix `13295`, `wb…`).
- `dto`: the HTTP `/v1` API request/response types.

Consumed as a sibling path-dep alongside `warrenguard` (for `ExitId`). Design:
`warren-core/docs/49-PHASE5-CLIENT-CONVERGENCE.md`.
