# Security and Deployment Notes

The SDK is a client-side protocol participant in your application's trust boundary. ThunderID remains authoritative for access-token issuance, token exchange policy, permissions, and revocation. The SDK does not supply an access-token validator or API authorization middleware. Never use `decode_jwt_token()` output to authorize a request, interpret actor delegation, or select a trusted issuer.

## Transport and identity validation

Discovery requires an exact issuer match. Endpoint overrides and discovery endpoints are checked against the configured origin and explicit HTTPS trust extensions. Matching uses parsed origin and path boundaries. HTTP redirects are refused; TLS certificate and hostname checks cannot be disabled. Plain HTTP is limited to loopback redirect-mode development. Embedded credential submission requires HTTPS even on loopback. A custom CA bundle or validating SSL context supports private development certificates.

Returned ID tokens are verified against trusted JWKS, with an allowlist of asymmetric algorithms, issuer/client audience, lifetime and mandatory claims, authorized-party checks, and nonce for OpenID Connect redirect completion. JWKS are cached; signature/key failures permit a bounded rate-limited refresh. Token-provided `jku`/`x5u` key locations are rejected. Signature validity does not make an ID token appropriate as an API bearer credential.

Authorization-code flows always generate S256 PKCE, random state and nonce. The same live client must complete the callback; state is one-use and expires after ten minutes. Server registration must independently constrain callback URLs. The SDK cannot secure a callback URL that your application exposes incorrectly.

## Sessions and secret handling

Default persistence uses a native OS credential store and fails closed for unsupported backends. `MemoryStorage` explicitly opts into process-only storage. Custom adapters must provide secure confidentiality and atomic writes. OS protection does not protect secrets from a compromised application process, debugger, or device.

A client receives a unique context by default. Use a separate client for each user/session in a multi-user service. Supplying `instance_id` deliberately reuses the persisted storage namespace for matching issuer/client/mode; avoid accidental cross-user reuse. Imported/restored sessions do not acquire interactive OBO provenance.

Refresh is serialized with primary-session updates and sign-out. Sign-out attempts server revocation before clearing primary state and reports revocation failure while still clearing locally. `clear_session()` clears only locally. `aclose()` releases resources and invalidates local pending/delegation ownership but does not sign out or erase persisted primary state. Call `sign_out()` explicitly when you intend session termination.

Reusable machine-token values use the configured secure adapter with separate per-client, resource, scope, and lifecycle keys. Their in-process index contains only lookup and expiry metadata. CIBA request state remains local; returned CIBA tokens belong to the caller, with only weak ownership references retained by the SDK. Signing out, clearing, closing, or successful reinitialization invalidates that state and deletes auxiliary machine-token keys. Storage errors propagate without falling back to a plaintext cache. In-flight agent writes finish before cleanup, and stale agent/CIBA responses cannot repopulate a cleared context. Clearing a cache cannot revoke bearer tokens already returned to callers; this release does not revoke agent/CIBA tokens on sign-out. Their remote lifetime and revocation remain the deployment's responsibility.

The SDK does not print tokens and sanitizes its errors. Credential fields are hidden from model/config representations, but callers can still expose them by serializing objects, logging callback URLs, enabling external HTTP tracing, or logging flow data. Keep bearer tokens out of environment-variable stores, query strings, screenshots, and logs. Use trusted application secret provisioning for configured client credentials. Python cannot reliably erase immutable secret strings from process memory.

## Delegation and backchannel boundaries

`get_agent_token()` represents the confidential client; it does not gain human permissions by itself. Specify resource and permission scopes intentionally. The SDK separates cache entries by resource/scope set, while the server enforces granted permissions and actor claims.

OBO authorization is explicit. A current interactive session or owned CIBA response reuses an existing token without silently changing its target. Different targets require explicit token exchange. `TokenExchangeAuthorization` is caller-supplied authorization material; the server validates its subject/actor authority. Local decoded claims never establish that authority.

CIBA supports polling only. The original request object belongs to its initiating client. Polling respects intervals, increases intervals after `slow_down`, stops on terminal errors, and uses a monotonic deadline. Cancellation stops local polling and invalidates the request; it does not cancel remote approval. The server remains responsible for associating `auth_req_id` with the authenticated client, verifying the approver, and enforcing one-time token delivery. Poll mode does not require the push-mode request-binding claim in ID tokens; if present, the SDK checks it.

## Current boundaries

No DPoP, JWE/encrypted ID tokens, backchannel logout endpoint, cross-instance logout propagation, isolated browser storage, authorization middleware, or background refresh is supplied. Applications that need those features must use an explicitly designed integration rather than weakening mandatory checks. Process-local cache metadata and CIBA ownership are not coordinated across replicas. Auxiliary machine-token entries are deleted during orderly lifecycle cleanup; abrupt process termination can leave entries in the OS credential store. The cache index is not restored after restart, so deployments must include expired-entry cleanup in credential-store operations. Returned CIBA/exchange tokens and configured client credentials necessarily reside in host memory; the SDK does not persist an additional copy of these results. The application owns any further caching or persistence. The host application controls where a returned bearer token is sent, so attach it only to its intended trusted API.

The [canonical SDK threat model](https://github.com/thunder-id/thunderid/blob/main/docs-internals/sdk-development/threat-model.md) defines the shared baseline. The [API reference](reference.md) records Python behavior and unsupported features. Offline tests validate protocol and security behavior; a passing mock test does not prove a particular deployment's registration, flow, approval-channel, or permission policy is configured correctly.
