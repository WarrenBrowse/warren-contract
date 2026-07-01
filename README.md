# warren-contract

The neutral client<->server contract shared by the Warren client SDK
(`warren-sdk-rs`) and the Warren backend (`warren-core`), so the wire contract
cannot drift between them.

- `ss58`: the wallet-identity address codec (Warren prefix `13295`, `wb…`).
- `auth`: the X-Warren canonical signing message plus the four `X-Warren-*`
  header-name constants.
- `dto`: the HTTP `/v1` API request/response types.

Each of the three has golden tests here, so the frozen behavior is pinned in one
place. `warren-core` re-exports these (`warren-api-types` from `dto`, `warren-ss58`
from `ss58`, `warren-identity::auth` from `auth`) and the SDK does the same
(`warren-api::dto`, `warren-identity::ss58`, `warren-identity::signing`), so the
contract has a single home and cannot drift between client and backend.

Consumed as a sibling path-dep alongside `warrenguard` (for `ExitId`). Design:
`warren-core/docs/49-PHASE5-CLIENT-CONVERGENCE.md`.
