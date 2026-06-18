ADR / RFC: GophKeeper Security Scheme v4.0

Status
Accepted

Date
2025-08-21

Context

GophKeeper is a client-server application for secure storage and synchronization of user secrets in an untrusted server environment. The security model is based on local-first operation, zero-knowledge client-side encryption, and passwordless identity bound to a single registered SSH Ed25519 key available through ssh-agent. The server acts as a blind persistence and synchronization layer and must not gain access to plaintext user data, AccountUnlockKey, DeviceKEK, or AccountMasterKey at any stage.

The design explicitly rejects the master-password model. Instead, user authentication, bootstrap access, and key derivation are based on proof of possession of the registered SSH key through two separate signing flows. A deterministic derivation signature is used only for local derivation of AccountUnlockKey. A one-time challenge signature is used only for server-side authentication and replay protection. These signatures are never interchangeable.

The protected unit is not the operating system device as a whole, but a specific local SQLite file acting as an autonomous cryptographic container. Each container has its own DeviceID, its own mTLS key pair, its own client certificate, its own DeviceMasterKeyEnvelope, and its own encrypted local copy of the mTLS private key. This means the architecture separates account bootstrap access from container-local device-bound protection.

Security goals

The scheme must ensure that the server cannot decrypt user secrets or recover any key-encryption keys. The user must not enter passwords, PIN codes, or mnemonic recovery phrases. Offline theft of the PostgreSQL server database must not reveal user secrets. Offline extraction of a local SQLite file from disk must not allow decryption on another host without access to the corresponding SSH signing capability. Replay of critical registration and device-attach messages must be prevented. AccountSalt and AccountBootstrapEnvelope must not be released by the server before successful challenge authentication during device attachment. The local mTLS private key must be encrypted under a container-specific DeviceKEK rather than a shared account-level unlock key.

Threat model boundaries

The main cryptographic assumption is that the ability to recover AccountMasterKey is equivalent to the ability to obtain a deterministic signature over DerivationPayload from the registered SSH private key and, independently, to produce a valid signature over a one-time ChallengePayload for server authentication. Local protection of a concrete SQLite container additionally depends on correct derivation of DeviceKEK from AccountUnlockKey and the raw DeviceID.

Any subject with effective access to SSH_AUTH_SOCK, ssh-agent, or another compatible signing mechanism for the registered SSH key must be considered fully capable of decrypting the vault. The client runtime does not implement a secondary interactive factor and delegates protection of the root signing capability to host operating system controls around agent access. If a hostile process can issue sign requests to the agent socket, the local vault is considered compromised regardless of file permissions such as 0600 on the SQLite file.

The scheme is intended to resist full compromise of server-side storage, interception or modification of gRPC traffic, and offline extraction of local client files from disk. It does not claim protection against a fully compromised client operating system during runtime, abusive use of SSH_AUTH_SOCK, extraction of secrets from process memory after unlock, or actions of a privileged local administrator.

Decision summary

GophKeeper Security Scheme v4.0 adopts a two-layer key protection model. A single AccountMasterKey encrypts all user records. A single AccountUnlockKey is deterministically derived locally from the canonical Ed25519 derivation signature and AccountSalt. For each local container, a distinct DeviceKEK is derived from AccountUnlockKey and DeviceID. The AccountMasterKey is encrypted into two distinct envelopes: AccountBootstrapEnvelope under AccountUnlockKey for account bootstrap and new-device attachment, and DeviceMasterKeyEnvelope under DeviceKEK for normal local operation. The local MtlsPrivateKey is encrypted only under DeviceKEK of that container.

The server stores encrypted record payloads, one AccountBootstrapEnvelope per account in MVP, account metadata, device registry metadata, challenge sessions, and certificate-related data. The server never receives DerivationSignature, never receives AccountUnlockKey, never computes DeviceKEK, and never sees AccountMasterKey in plaintext.

Architectural principles

The scheme follows zero-knowledge operation. All encryption and decryption of user data are performed only on the client. The server stores ciphertext and open metadata required for routing, synchronization, and device lifecycle management. The server is intentionally blind with respect to the contents of user secrets.

The scheme is passwordless. User identity is based entirely on asymmetric SSH cryptography. The client never reads the private SSH key directly and never transmits it over the network. All signing operations are delegated to ssh-agent.

The client operates in local-first mode. All create, set, update, and delete operations are committed atomically into the local SQLite file. Network exchange is isolated into an explicit synchronization command. This improves autonomy, availability under network loss, and predictability of local writes.

Domain separation is mandatory. Different payload contexts and HKDF info values are used for account unlock derivation, device KEK derivation, challenge authentication, envelope AAD schemas, and record encryption. This prevents unsafe reuse of cryptographic material across functions.

A strict separation exists between derivation signing and authentication signing. DerivationSignature is computed over a stable DerivationPayload and is used only as KDF input on the client. AuthChallengeSignature is computed over a one-time ChallengePayload and is used only to prove possession of the SSH key to the server. The server does not use challenge signatures for key derivation. The client does not use challenge signatures as KDF input.

Cryptographic algorithms

The only supported user key type in MVP is software OpenSSH Ed25519. Hardware tokens, FIDO2-based keys, and any signing mechanism with non-deterministic signatures are outside MVP scope because deterministic derivation is required. The transport layer uses TLS 1.3 with server authentication based on an embedded ServerCA, with optional deployment under standard public TLS such as Let’s Encrypt. Symmetric encryption for records and key envelopes uses XChaCha20-Poly1305. Key derivation uses HKDF-SHA256. Hashing uses SHA-256. Randomness is sourced from the operating system CSPRNG through crypto/rand.

Core entities and key materials

The key hierarchy includes SshPublicKey, SshPrivateKey in ssh-agent, SshFingerprint, AccountSalt, AccountUnlockKey, DeviceKEK, AccountMasterKey, AccountBootstrapEnvelope, DeviceMasterKeyEnvelope, UserID, DeviceID, ServerUrl, EncryptedMtlsPrivateKey, ClientCertificate, SessionID, and ServerNonce.

AccountUnlockKey is never stored. It is derived locally from the canonical 64-byte Ed25519 derivation signature and AccountSalt using HKDF-SHA256 with the info string gophkeeper-account-unlock-v1. DeviceKEK is never stored. It is derived locally from AccountUnlockKey and the raw 16-byte DeviceID using HKDF-SHA256 with the info string gophkeeper-device-kek-v1. AccountMasterKey exists only in client memory during active use and is the sole data-encryption root for user records.

A single account has one AccountMasterKey and one AccountUnlockKey. Each local container has a unique DeviceKEK, DeviceMasterKeyEnvelope, mTLS key pair, encrypted mTLS private key, and certificate. The server stores one AccountBootstrapEnvelope in MVP. Each SQLite file stores its own DeviceMasterKeyEnvelope and its own encrypted mTLS private key.

Security consequences

This model gives one stable account-level unlock path through SSH possession and AccountSalt, but ensures each local container has its own cryptographic wrapping state. Theft of one local SQLite file does not automatically imply compromise of transport identity of another SQLite file because each mTLS private key is wrapped under its own DeviceKEK. Likewise, compromise of server-side bootstrap data alone does not expose user records because the server lacks the SSH-based derivation capability required to recover AccountUnlockKey.

Key derivation and payload formats

Before first registration the client must execute a determinism self-test. It requests identities from ssh-agent, signs the same DerivationPayload twice, and compares the resulting Ed25519 signatures byte for byte. If the signatures differ, the key is unsupported for MVP and registration must fail. This requirement exists because AccountUnlockKey derivation depends on deterministic signing output.

The client must canonicalize the ssh-agent signature result. Only raw Ed25519 R concatenated with S, exactly 64 bytes, may be fed into HKDF. The surrounding SSH framing and algorithm wrappers are forbidden as KDF input. The algorithm type must be strictly verified as ssh-ed25519.

DerivationPayload is stable and deterministic. It includes version as uint32 big-endian, the context string gophkeeper-account-unlock-v1 encoded as uint16 length plus bytes, user_id encoded as uint16 length plus raw UUID bytes, and ssh_fingerprint encoded as uint16 length plus raw fingerprint bytes. DerivationPayload must not contain SessionID, ServerNonce, timestamps, or any other ephemeral field.

ChallengePayload is separate and one-time. It includes version as uint32 big-endian, the context string gophkeeper-auth-challenge-v1 encoded as uint16 length plus bytes, user_id encoded as uint16 length plus raw UUID bytes, session_id encoded as uint16 length plus raw UUID bytes, server_nonce encoded as uint16 length plus raw bytes, and operation encoded as uint16 length plus bytes. Allowed operations are register and attach-device. ChallengePayload is used only for AuthChallengeSignature inside a single challenge session.

Derivation formulas are fixed. AccountUnlockKey equals HKDF-SHA256 over derivation_signature using AccountSalt as salt, gophkeeper-account-unlock-v1 as info, and output length 32. DeviceKEK equals HKDF-SHA256 over AccountUnlockKey using DeviceID_raw as salt or context input as specified, gophkeeper-device-kek-v1 as info, and output length 32. Neither AccountUnlockKey nor DeviceKEK is ever transmitted to the server.

Envelope formats and AAD

All encrypted objects are represented as versioned envelopes containing version, algorithm identifier, nonce, aad_schema identifier, and ciphertext with authentication tag. The algorithm is XChaCha20-Poly1305 and the nonce length is 24 bytes.

AccountBootstrapEnvelope AAD includes version 1, schema gophkeeper-account-bootstrap-aad-v1, user_id, and ssh_fingerprint. DeviceMasterKeyEnvelope AAD includes version 1, schema gophkeeper-device-master-key-aad-v1, user_id, and device_id. EncryptedMtlsPrivateKey AAD includes version 1, schema gophkeeper-mtls-private-key-aad-v1, user_id, and device_id. RecordEnvelope AAD includes version 1, schema gophkeeper-record-aad-v1, user_id, and record_id. Each AAD context binds ciphertext to its intended semantic scope and helps detect substitution attacks across containers, users, or record identities.

SQLite local container

The SQLite file is the local cryptographic container. The device_state table is constrained by a single-row invariant with CHECK id equals 1. It stores server_url, user_id, device_id, ssh_public_key, device_master_key_envelope, account_bootstrap_envelope, encrypted_mtls_private_key, and client_certificate. AccountBootstrapEnvelope may be cached locally for future bootstrap-related operations, but normal runtime must unlock AccountMasterKey through DeviceMasterKeyEnvelope.

File-system protection is part of the local boundary. On Unix, the database file must use mode 0600 and its directory mode 0700. On Windows, access must be limited by ACL to the current user SID. SQLite must enable foreign_keys, use a busy timeout of 5000 milliseconds, and run in WAL mode.

Operationally, this means the local container is protected both by host file permissions and by cryptographic wrapping. The permissions help reduce accidental disclosure, while the actual secrecy of the vault depends on possession of the SSH signing capability and the ability to derive the correct DeviceKEK for the specific container.

Registration flow for the first SQLite container

The registration protocol consists of RegisterBegin and RegisterFinish. In RegisterBegin, the client obtains SshPublicKey from ssh-agent and sends RegisterBegin with Username and SshPublicKey. The server verifies username uniqueness, generates UserID, AccountSalt, SessionID, ServerNonce, and creates a challenge session for the register operation. The server returns UserID, AccountSalt, SessionID, and ServerNonce.

The client then forms DerivationPayload, requests DerivationSignature from ssh-agent, canonicalizes the raw Ed25519 signature, and derives AccountUnlockKey. It generates a random 32-byte AccountMasterKey. It encrypts AccountMasterKey under AccountUnlockKey into AccountBootstrapEnvelope. It generates DeviceID, derives DeviceKEK, encrypts the same AccountMasterKey under DeviceKEK into DeviceMasterKeyEnvelope, generates an mTLS key pair and CSR, and encrypts the mTLS private key under DeviceKEK. Separately, it forms ChallengePayload for the register operation and requests AuthChallengeSignature from ssh-agent.

The client sends RegisterFinish containing UserID, SessionID, AuthChallengeSignature, DeviceID, AccountBootstrapEnvelope, DeviceMasterKeyEnvelope, and CSR. The server validates the challenge session, verifies AuthChallengeSignature specifically over ChallengePayload, checks the operation match, checks that the challenge is unexpired and unused, atomically marks it used, issues a client certificate, stores account and device metadata atomically, and returns ClientCertificate.

Device attachment flow

To add a new device, the user must have access to the same registered SSH key via a local ssh-agent, forwarded agent, or another agent-compatible signing mechanism. The new local container will receive its own DeviceID, its own mTLS key pair, its own certificate, a local copy of AccountBootstrapEnvelope, its own DeviceMasterKeyEnvelope, and local sync metadata.

The client starts with AttachDeviceBegin carrying SshPublicKey. The server resolves the account by SshPublicKey or SshFingerprint, creates a challenge session for attach-device, and returns only UserID, SessionID, and ServerNonce. At this stage the server must not return AccountSalt or AccountBootstrapEnvelope.

The client creates ChallengePayload for attach-device and requests AuthChallengeSignature from ssh-agent. It sends AttachDeviceAuth with UserID, SessionID, and AuthChallengeSignature. The server verifies the signature over the expected payload, validates TTL and unused state, and atomically moves the session to authenticated. Only after that does it return AccountSalt and AccountBootstrapEnvelope.

The client then forms the stable DerivationPayload, requests a separate DerivationSignature, derives AccountUnlockKey, decrypts AccountBootstrapEnvelope, and recovers AccountMasterKey locally. It generates a new DeviceID, derives DeviceKEK, encrypts AccountMasterKey into DeviceMasterKeyEnvelope, generates a new mTLS key pair and CSR, encrypts the local mTLS private key under DeviceKEK, and persists local state in SQLite. It then sends AttachDeviceFinish with UserID, SessionID, DeviceID, DeviceMasterKeyEnvelope, and CSR. The server confirms the session is in authenticated state, confirms the operation is attach-device, registers DeviceID, stores device metadata, issues a client certificate, marks the attach session completed and non-reusable, and returns ClientCertificate and optionally the CA chain.

Challenge sessions and replay protection

All critical control-plane operations use one-time challenge sessions. A challenge session contains SessionID as a random UUID, ServerNonce from a CSPRNG, UserID, Operation, CreatedAt, ExpiresAt equal to CreatedAt plus five minutes, and a state flag initially set to unused.

The server accepts AuthChallengeSignature only when all required checks pass. SessionID must exist. The challenge must belong to the expected operation. The challenge must not be expired. The state must allow the current transition. The SSH signature must validate against the registered SshPublicKey. The user_id, session_id, server_nonce, and operation embedded in the serialized ChallengePayload must exactly match the values stored server-side. After successful verification the server must atomically move the state from unused to used for registration, or from unused to authenticated for attach authorization. A later successful AttachDeviceFinish moves authenticated to completed. Reuse of the same SessionID is forbidden.

Replay resistance is achieved at two levels. First, registration and attachment require signatures over one-time payloads that bind SessionID, ServerNonce, and Operation. Even if a signature is observed, it cannot be replayed once the state changes or the TTL expires. Second, communication is protected by TLS 1.3 or mTLS, which prevents silent modification and unauthorized message injection on the transport channel.

Blind synchronization

The sync command operates only inside an mTLS session associated with a specific SQLite container. The client derives AccountUnlockKey, derives DeviceKEK from its DeviceID, decrypts AccountMasterKey from DeviceMasterKeyEnvelope, reads local modified records, and uploads record ciphertexts and sync metadata. The server stores ciphertext and synchronization metadata and returns encrypted deltas from other devices belonging to the same account. The server is never able to decrypt the payloads.

The server allows sync only when the presented client certificate is valid, has clientAuth extended key usage, contains a SAN URI of the form urn:gophkeeper:file:uuid, is not revoked, and maps to a DeviceID that belongs to the authenticated account. This makes network sync dependent on per-container transport identity rather than only on account metadata.

mTLS identity and device lifecycle

Each SQLite container has a unique and revocable network identity consisting of DeviceID, mTLS private key, and client certificate issued by the server root CA. During sync the client decrypts EncryptedMtlsPrivateKey using DeviceKEK and brings up an mTLS channel. The server rejects the TLS handshake if the certificate is absent, invalid, missing clientAuth EKU, missing the expected SAN URI, revoked, or mismatched with the device registry.

For each device the server stores DeviceID, the public portion of ClientCertificate, status active or revoked, registration time, and last synchronization time. On revocation the server marks the DeviceID revoked, blocks the certificate, denies new sync sessions, and leaves AccountMasterKey unchanged. Other devices continue to work and user records do not require re-encryption. Device status changes are logged in audit_device_events with event_id, timestamp, user_id, device_id, action, and operator_ip.

Certificate lifecycle and runtime hygiene

The client certificate TTL is thirty days. Automatic refresh is performed during sync if less than seven days remain before expiration. Reuse of a serial number is forbidden and blocked by a unique index in PostgreSQL. Certificate revocation is enforced at the server gRPC interception layer through current device status.

After sensitive operations the client must clear AccountMasterKey, AccountUnlockKey, DeviceKEK, DerivationSignature, AuthChallengeSignature if buffered, and the decrypted mTLS private key from memory. In Go, runtime.KeepAlive is used to reduce the risk of compiler optimizations interfering with intended lifetime management. These measures reduce exposure time in RAM but do not provide secure-memory guarantees and do not defend against full host compromise.

MVP constraints

The MVP supports only one SSH key per account, no SSH key rotation, no emergency recovery, and no multi-key server structures. Loss of the original SSH private key means permanent loss of access to both local and cloud data. The server has no capability to reset or recover keys. This is a deliberate product boundary rather than an implementation gap.

Formal security invariants

The implementation is considered correct only if the following invariants hold. AccountUnlockKey can be computed only locally from DerivationSignature, AccountSalt, and the fixed HKDF context. DeviceKEK can be computed only locally from AccountUnlockKey, raw DeviceID bytes, and the fixed HKDF context. DerivationSignature and AuthChallengeSignature are generated over different payloads and are never interchangeable. The server never accepts reuse of AuthChallengeSignature for the same SessionID. The server never releases AccountSalt or AccountBootstrapEnvelope before successful challenge authentication in the attach flow. AccountMasterKey is never transmitted to the server in plaintext. All user records are encrypted only under AccountMasterKey. In normal operation the local container unlocks AccountMasterKey through DeviceMasterKeyEnvelope. Each MtlsPrivateKey is encrypted only under the DeviceKEK of its own container. All synchronization traffic occurs only inside TLS 1.3 or mTLS.

Minimum server requirements

The server must store challenge sessions with TTL and one-time state, atomically enforce state transitions unused to used and unused to authenticated to completed, reject repeated SessionID usage, verify Operation against the invoked RPC, log failed and successful registration and attachment attempts, rate limit by IP and SshFingerprint, store AccountBootstrapEnvelope as the sole cloud bootstrap envelope in MVP, and maintain the device registry plus certificate status.

Minimum client requirements

The client must run the deterministic-signature self-test, canonicalize Ed25519 signatures to raw 64-byte form, serialize DerivationPayload and ChallengePayload deterministically, never use AuthChallengeSignature as KDF input, never send DerivationSignature to the server, derive DeviceKEK only from AccountUnlockKey and DeviceID, use DeviceMasterKeyEnvelope as the primary local working envelope, and wipe critical secrets after use.

Consequences, rationale, and future evolution

This design gives a coherent zero-knowledge and passwordless scheme suitable for MVP implementation and formal defense. It preserves a strong separation of concerns between account bootstrap, local container protection, and transport identity. The account bootstrap path is based on SSH possession and deterministic derivation. The local working path is based on per-container DeviceKEK and DeviceMasterKeyEnvelope. The network path is based on per-container mTLS credentials encrypted under the same DeviceKEK. As a result, compromise of the server database does not reveal user secrets, replay of critical control-plane requests is constrained by one-time challenge sessions, and offline theft of a local SQLite file does not bypass the need for SSH-based derivation capability.

The chosen tradeoff is intentional. The model does not attempt to defend against a hostile runtime environment that can control ssh-agent access or inspect process memory after unlock. This is acceptable for the stated threat model because the trust root is explicitly delegated to ssh-agent and host controls around it. The design also avoids the complexity of a full multi-key access matrix in MVP.

The separation between AccountBootstrapEnvelope and DeviceMasterKeyEnvelope is the main architectural decision. It allows new devices to bootstrap into the account without re-encrypting all user data, while keeping day-to-day operation tied to the specific local container through DeviceKEK. Encrypting MtlsPrivateKey under DeviceKEK instead of AccountUnlockKey further ensures that transport identity remains container-bound and revocable on a per-device basis.

Future migration after MVP is straightforward because AccountMasterKey is already decoupled from the SSH key. To support multiple SSH keys and key rotation, the system only needs to evolve from storing one AccountBootstrapEnvelope per account to storing a set of AccountBootstrapEnvelopes keyed by ssh_fingerprint. Existing DeviceMasterKeyEnvelope values, DeviceID assignments, AccountMasterKey, and all RecordEnvelope ciphertexts can remain unchanged. A new SSH key would be added by proving possession, deriving a new AccountUnlockKey for that key, and creating an additional bootstrap envelope for the same AccountMasterKey. Revoking an old SSH key would invalidate only the corresponding bootstrap envelope while existing local containers continue operating through their stored DeviceMasterKeyEnvelope values.

Decision

Approve GophKeeper Security Scheme v4.0 as the normative MVP security architecture. All client and server implementations must follow the described key hierarchy, payload separation, challenge-state machine, envelope semantics, local container model, and mTLS device identity rules exactly. Any deviation affecting derivation inputs, signature roles, challenge transitions, AAD composition, or release conditions for AccountSalt and AccountBootstrapEnvelope is considered a security-breaking change and requires a new ADR or RFC revision.

