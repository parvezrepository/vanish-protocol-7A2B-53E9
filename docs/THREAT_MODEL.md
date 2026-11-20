# VANISH Threat Model & Formal Security Analysis

---

## 1. Adversary Model & Assumptions

In security and privacy research, systems must rigorously define adversary capabilities and boundaries.

### 1.1 In-Scope Adversary Capabilities
- **Active Network Adversary:** An attacker who intercepts, alters, reorders, or replays `.vfile` containers during transmission.
- **Local Time-Rollback Attacker:** An unprivileged or semi-privileged local user who alters system wall-clock time backwards to postpone file expiration.
- **Header & Manifest Tamperer:** An attacker who modifies timestamps or changes the expiry policy inside `.vfile` files.
- **Passive Lingering Data Recoverer:** Forensic scrapers seeking undeleted temporary files or stale file allocation table remnants.

### 1.2 Out-of-Scope (Fundamental Boundaries)
- **The Analog Hole:** A user who takes a physical photograph of the monitor screen or uses external HDMI capture devices.
- **Root / Kernel Compromise with Live Memory Dumping:** A root user with kernel debugger capabilities actively dumping plaintext buffers during decrypted execution. (No software-level DRM or file protocol can mathematically resist a kernel-level memory interceptor).

---

## 2. Operational Security Tiers

```
+-------------------------------------------------------------------------+
| Tier 1: Cooperative Hygiene (Consumer & Enterprise Endpoints)           |
| - Standard OS storage management sweeps and removes expired files.       |
| - Prevents data retention liability, stale document leakage, compliance |
|   infractions (GDPR Right to Be Forgotten).                             |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
| Tier 2: OS-Sandboxed Key Revocation (Cryptographic Erasure)              |
| - Payload encrypted with AES-256-GCM.                                   |
| - Key stored in OS KeyStore / Keystore daemon.                           |
| - At t >= t_exp, KeyStore destroys decryption key; ciphertext becomes    |
|   permanently unrecoverable even if backups exist.                      |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
| Tier 3: Hardware Monotonic Roots of Trust (Anti-Clock Rollback)          |
| - Enforces hardware monotonic counters (TPM 2.0 / ARM TrustZone RPMB).  |
| - Validates time against authenticated network time (Roughtime / NTS).   |
+-------------------------------------------------------------------------+
```

---

## 3. Attack Analysis & Proof Sketches

### Lemma 1 (Manifest Tamper Resistance)
*No polynomial-time adversary $\mathcal{A}$ can alter the expiry timestamp $t_{\text{exp}}$ to $t'_{\text{exp}} > t_{\text{exp}}$ without invalidating the container signature under the standard EUF-CMA security of Ed25519.*

**Proof Sketch:**  
The Ed25519 signature is evaluated over $\text{SHA256}(\text{Header}_{0:26} \mathbin{\Vert} \text{PubKey} \mathbin{\Vert} \text{Nonce} \mathbin{\Vert} \text{Manifest}_{\text{CBOR}} \mathbin{\Vert} \text{SHA256}(\text{Payload}))$.  
Altering $t_{\text{exp}}$ modifies $\text{Manifest}_{\text{CBOR}}$. Under SHA-256 collision resistance, $\text{Digest}' \ne \text{Digest}$. By the Existential Unforgeability under Chosen Message Attack (EUF-CMA) of Ed25519, $\mathcal{A}$ cannot forge a valid signature for $\text{Digest}'$ without knowing the issuer's private key.

### Lemma 2 (Forward Secrecy via Key Revocation)
*Under Tier 2 (Encrypted Mode), an attacker who acquires the local storage drive after $t \ge t_{\text{exp}}$ cannot recover the plaintext payload even with physical drive forensics.*

**Proof Sketch:**  
The payload is encrypted under AES-256-GCM with a high-entropy 256-bit key $K$. At $t \ge t_{\text{exp}}$, the OS daemon scrubs $K$ using memory zeroization and deletes $K$ from the secure keystore. Without $K$, decryption requires breaking AES-256 IND-CPA security, which is computationally infeasible.
