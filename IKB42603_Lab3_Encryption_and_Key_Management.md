# IKB42603 Cloud Computing Security Essentials
## Lab 3 — Data Protection: Encryption & Key Management
**At-rest & in-transit encryption, envelope encryption and cryptographic erasure — OpenSSL & LocalStack KMS**

| | |
|---|---|
| **Course** | IKB42603 Cloud Computing Security Essentials |
| **Lab** | Lab 3 · Weeks 5–6 |
| **Student** | MUHAMED HAMIRUL BIN MOHD BAZRI |
| **Institution** | UniKL MIIT |


---

## Objective

This lab aims to provide hands-on experience with encryption and key management techniques used in cloud environments. Students will apply symmetric (AES) and asymmetric (RSA) encryption, protect data in transit using TLS, manage keys using a Key Management Service (KMS), implement envelope encryption, perform cryptographic erasure, and verify data integrity using hashing.

---

## Learning Outcomes

By the end of this lab, students are able to:

1. **Encrypt and decrypt data** using symmetric (AES) and asymmetric (RSA) cryptography.
2. **Protect data in transit** with TLS and observe the difference between plaintext and encrypted traffic.
3. **Use a Key Management Service (KMS)** and implement envelope encryption.
4. **Apply per-tenant keys** and perform cryptographic erasure to make data provably unrecoverable.
5. **Verify data integrity** with hashing and build a tamper-evident (hash-chained) record.

---

## Environment

| Component | Details |
|---|---|
| **Operating System** | Kali Linux (running via terminal) |
| **Cryptography Tool** | OpenSSL |
| **Container Runtime** | Docker |
| **KMS (Simulated)** | LocalStack (AWS KMS emulated at `http://localhost:4566`) |
| **Web Server** | NGINX (Docker container) |
| **AWS CLI** | Version 2, pointed at LocalStack endpoint |
| **Shell** | Zsh (Kali Linux default) |

---

## Session A (Week 5) — Encryption Fundamentals

---

### Task 1 — Symmetric Encryption (Data at Rest)

**What this task is about:**
Symmetric encryption uses **one shared key** to both encrypt and decrypt data. We use AES-256, which is one of the strongest standard encryption algorithms. This protects data "at rest" — meaning data that is stored (not moving).

**Steps performed:**

**Step 1:** Create a sensitive text file.
```bash
echo 'Patient: Ahmad Hakim, Diagnosis: confidential' > record.txt
```

**Step 2:** Encrypt the file using AES-256-CBC with PBKDF2 key derivation (password used: `123456`).
```bash
openssl enc -aes-256-cbc -pbkdf2 -salt -in record.txt -out record.enc
```

**Step 3:** View the encrypted file to confirm it is unreadable.
```bash
cat record.enc
```
The output shows scrambled/binary characters — confirming the file is encrypted and cannot be read without the key.

**Step 4:** Decrypt the file back to its original form and verify it matches.
```bash
openssl enc -d -aes-256-cbc -pbkdf2 -in record.enc -out record.dec.txt
diff record.txt record.dec.txt && echo 'MATCH: decryption successful'
```

**Evidence — Task 1:**

![Task 1 — Symmetric Encryption (Data at Rest)](Task%201%20—%20Symmetric%20Encryption%20(Data%20at%20Rest).png)

**Result:** The terminal shows `MATCH: decryption successful` — confirming the file was encrypted and then correctly decrypted back to its original content.

---

**📝 Short-Answer Question (from Task 1):**

> **Q: What is the key-distribution problem with symmetric encryption, and why does it matter for the cloud?**

**Answer:**
The key-distribution problem is: **how do you safely share the secret key with the other person?** Both the sender and the receiver need the same key — but if you send the key over the internet, an attacker can intercept it. In the cloud, this is a big problem because data moves between many servers, users, and services at large scale. If one key is stolen, all data encrypted with that key is exposed. That is why cloud platforms use KMS (Key Management Service) to handle key distribution safely.

---

### Task 2 — Asymmetric Encryption & Digital Signatures

**What this task is about:**
Asymmetric encryption uses **two keys** — a public key (to encrypt) and a private key (to decrypt). It also supports **digital signatures** — using the private key to sign, and the public key to verify. This is how identity and authenticity are proven online.

**Steps performed:**

**Step 1:** Generate a 2048-bit RSA key pair (private key + public key).
```bash
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
```

**Step 2:** Encrypt the file using the **public key**, then decrypt using the **private key**.
```bash
openssl pkeyutl -encrypt -pubin -inkey public.pem -in record.txt -out record.rsa
openssl pkeyutl -decrypt -inkey private.pem -in record.rsa -out record.rsa.txt
```

**Step 3:** Sign the file using the **private key**, then verify the signature using the **public key**.
```bash
openssl dgst -sha256 -sign private.pem -out record.sig record.txt
openssl dgst -sha256 -verify public.pem -signature record.sig record.txt
```

**Evidence — Task 2:**

![Task 2 — Asymmetric Encryption & Digital Signatures](Task%202%20—%20Asymmetric%20Encryption%20&%20Digital%20Signatures.png)

**Result:** The terminal shows `Verified OK` — confirming that the digital signature is valid and the file has not been tampered with.

---

### Task 3 — Encryption in Transit (TLS)

**What this task is about:**
TLS (Transport Layer Security) encrypts data **while it is travelling** across the network. Without TLS, any attacker on the same network can read the data (eavesdropping). With TLS, even if the data is intercepted, it looks like random noise.

**Steps performed:**

**Step 1:** Start LocalStack (if not running).
```bash
docker start localstack
```

**Step 2:** Generate a self-signed TLS certificate for localhost.
```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
  -days 7 -nodes -subj '/CN=localhost'
```

**Evidence — Task 3 Part 1 (Certificate generation):**

![Task 3 — Encryption in Transit (TLS) part 1](Task%203%20—%20Encryption%20in%20Transit%20(TLS)%20part%201.png)

**Step 3:** Configure NGINX to use HTTPS (SSL) by writing a custom `nginx.conf`.
```nginx
server {
    listen 443 ssl;
    server_name localhost;

    ssl_certificate /etc/nginx/cert.pem;
    ssl_certificate_key /etc/nginx/key.pem;

    location / {
        root /usr/share/nginx/html;
        index index.html;
    }
}
```

**Evidence — Task 3 Part 3 (nginx.conf configuration):**

![Task 3 — Encryption in Transit (TLS) part 3](Task%203%20—%20Encryption%20in%20Transit%20(TLS)%20part%203.png)

**Step 4:** Launch the NGINX container with TLS (HTTPS on port 8443), pulling the nginx image and mounting the certificate, key, and record file.
```bash
docker run -d --name tls \
  -p 8443:443 \
  -v $(pwd)/cert.pem:/etc/nginx/cert.pem:ro \
  -v $(pwd)/key.pem:/etc/nginx/key.pem:ro \
  -v $(pwd)/record.txt:/usr/share/nginx/html/record.txt:ro \
  -v $(pwd)/nginx.conf:/etc/nginx/conf.d/default.conf:ro \
  nginx
```

**Evidence — Task 3 Part 2 (pulling nginx image) and Part 4 (running container + curl test):**

![Task 3 — Encryption in Transit (TLS) part 2](Task%203%20—%20Encryption%20in%20Transit%20(TLS)%20part%202.png)

![Task 3 — Encryption in Transit (TLS) part 4](Task%203%20—%20Encryption%20in%20Transit%20(TLS)%20part%204.png)

**Step 5:** Access the file securely over HTTPS using `curl`.
```bash
curl -k https://localhost:8443/record.txt
```

**Result:** The terminal shows `Patient: Ahmad Hakim, Diagnosis: confidential` — the file was retrieved **securely over an encrypted HTTPS channel**. The `-k` flag accepts the self-signed certificate. After this, the container is stopped:
```bash
docker stop tls
```

---

## Session B (Week 6) — Key Management, Envelope Encryption & Erasure

---

### Task 4 — Create and Use a KMS Master Key

**What this task is about:**
A KMS (Key Management Service) manages encryption keys on behalf of users. Instead of managing keys yourself, KMS stores and protects them. Here we create a **Customer Master Key (CMK)** using LocalStack (which simulates AWS KMS locally).

**Steps performed:**

**Step 1:** Set the LocalStack endpoint variable.
```bash
EP='--endpoint-url=http://localhost:4566'
```

**Step 2:** Create a KMS Customer Master Key (CMK) for Tenant A.
```bash
aws $EP kms create-key --description 'CCSE mii-A master key'
```

**Evidence — Task 4 Part 1 (KMS key creation):**

![Task 4 — Create and Use a KMS Master Key part 1](Task%204%20—%20Create%20and%20Use%20a%20KMS%20Master%20Key%20part%201.png)

The key was created with:
- **KeyId:** `99831018-7895-484e-947b-d79cf9bf923c`
- **KeyState:** `Enabled`
- **KeyUsage:** `ENCRYPT_DECRYPT`

**Step 3:** Save the KeyId and encrypt a small secret directly with KMS.
```bash
KEY_A=99831018-7895-484e-947b-d79cf9bf923c
aws $EP kms encrypt --key-id $KEY_A \
  --plaintext "$(echo -n 'hello' | base64)" \
  --query CiphertextBlob --output text
```

**Evidence — Task 4 Part 2 (KMS encrypt output):**

![Task 4 — Create and Use a KMS Master Key part 2](Task%204%20—%20Create%20and%20Use%20a%20KMS%20Master%20Key%20part%202.png)

**Result:** KMS returned a **CiphertextBlob** — a Base64-encoded encrypted blob. The plaintext `hello` is now encrypted under the KMS master key.

---

### Task 5 — Envelope Encryption

**What this task is about:**
For large data, you don't encrypt directly with the master key — that would be slow and risky. Instead, you:
1. Ask KMS to generate a **data key** (a temporary key for encrypting your data).
2. Encrypt your actual data with the data key **locally** (fast).
3. Store the data key **wrapped (encrypted)** by the master key.
4. Delete the plaintext data key from disk — only the wrapped version remains.

This is called **envelope encryption** — the data is wrapped by the data key, which is wrapped by the master key.

**Steps performed:**

**Step 1:** Ask KMS to generate a data key (AES-256).
```bash
aws $EP kms generate-data-key \
  --key-id $KEY_A \
  --key-spec AES_256 \
  --query '[Plaintext,CiphertextBlob]' \
  --output text > datakeys.txt
```

**Step 2:** Split the output into plaintext key (`datakey.b64`) and encrypted key (`datakey.enc`).
```bash
cut -f1 datakeys.txt > datakey.b64
cut -f2 datakeys.txt > datakey.enc
```

**Step 3:** Decode the plaintext data key to binary and encrypt the file locally.
```bash
base64 -d datakey.b64 > datakey.bin
openssl enc -aes-256-cbc -pbkdf2 \
  -in record.txt \
  -out record.env.enc \
  -pass file:./datakey.bin
```

**Step 4:** Destroy the plaintext data key from disk — only keep the KMS-wrapped version.
```bash
rm datakey.bin datakey.b64
rm datakeys.txt
echo 'Only the KMS-wrapped data key (datakey.enc) remains.'
```

**Evidence — Task 5 (Envelope Encryption):**

![Task 5 — Envelope Encryption](Task%205%20—%20Envelope%20Encryption.png)

**Result:** `record.env.enc` was created (64 bytes, encrypted). The plaintext data key was deleted. Only `datakey.enc` (the KMS-wrapped key) remains on disk. To decrypt the data later, you must send `datakey.enc` back to KMS to unwrap it.

---

**📝 Short-Answer Question (from Task 5):**

> **Q3: Explain envelope encryption and why only the master key needs hardware-grade protection.**

**Answer:**
Envelope encryption is a two-layer system:
- The **data key** encrypts your actual data (local, fast).
- The **master key** encrypts/protects the data key (stored in KMS).

Only the master key needs hardware-grade protection (like an HSM — Hardware Security Module) because:
- There is only **one master key** to protect, not thousands of data keys.
- If the master key is safe, all data keys wrapped by it are also safe.
- Even if an attacker steals the encrypted data + encrypted data key, they cannot decrypt anything without the master key in KMS.

---

### Task 6 — Per-Tenant Keys & Cryptographic Erasure

**What this task is about:**
In a multi-tenant cloud, each customer (tenant) should have their **own separate encryption key**. This way, one tenant's data can never be read by another. When a tenant leaves or data must be deleted, you simply **destroy the key** — making the data permanently unreadable. This is called **cryptographic erasure**.

**Steps performed:**

**Step 1:** Create a second KMS key for Tenant B.
```bash
aws $EP kms create-key --description 'CCSE kim-B master key'
KEY_B=8a1fc61f-1a96-40df-9315-91f5ab28a797
```

**Step 2:** Check Tenant A's key state (currently still `Enabled`).
```bash
aws $EP kms describe-key \
  --key-id $KEY_A \
  --query 'KeyMetadata.{ID:KeyId,State:KeyState,Description:Description}' \
  --output table
```

**Evidence — Task 6 Part 1 (Tenant B key creation + Tenant A key state check):**

![Task 6 — Per-Tenant Keys & Cryptographic Erasure part 1](Task%206%20—%20Per-Tenant%20Keys%20&%20Cryptographic%20Erasure%20part%201.png)

**Step 3:** Schedule deletion of Tenant A's key (7-day pending window), then verify the state changed to `PendingDeletion`. Cancel the deletion to restore.
```bash
aws $EP kms schedule-key-deletion --key-id $KEY_A --pending-window-in-days 7
aws $EP kms describe-key --key-id $KEY_A \
  --query 'KeyMetadata.{ID:KeyId,State:KeyState,Description:Description}' \
  --output table
aws $EP kms cancel-key-deletion --key-id $KEY_A
```

**Evidence — Task 6 Part 2 (schedule deletion → PendingDeletion state → cancel):**

![Task 6 — Per-Tenant Keys & Cryptographic Erasure part 2](Task%206%20—%20Per-Tenant%20Keys%20&%20Cryptographic%20Erasure%20part%202.png)

**Step 4:** Disable the key immediately to simulate cryptographic erasure, then attempt to decrypt — it should fail.
```bash
aws $EP kms disable-key --key-id $KEY_A
aws $EP kms describe-key --key-id $KEY_A \
  --query 'KeyMetadata.{ID:KeyId,State:KeyState,Description:Description}' \
  --output table
aws $EP kms decrypt --ciphertext-blob fileb://datakey.enc 2>&1 | head -3
```

**Evidence — Task 6 Part 3 (disable key + failed decrypt attempt):**

![Task 6 — Per-Tenant Keys & Cryptographic Erasure part 3](Task%206%20—%20Per-Tenant%20Keys%20&%20Cryptographic%20Erasure%20part%203.png)

**Result:**
- Key state changed to `Disabled`.
- The `aws kms decrypt` command returned an **error**: `An error occurred (NotFoundException) when calling the Decrypt operation: Invalid keyId`.
- This proves that once the key is gone, `record.env.enc` is permanently unreadable — even the cloud provider cannot recover it.

---

**📝 Short-Answer Question (from Task 6):**

> **Q4: How does cryptographic erasure achieve provable deletion where overwriting cannot (in the cloud)?**

**Answer:**
In the cloud, when you delete a file, copies may still exist in backups, snapshots, or replicas — so "deleting" the file doesn't really erase all copies.

With **cryptographic erasure**, instead of deleting the data, you **destroy the encryption key**. Since the data is encrypted, without the key it is just meaningless noise — even if copies exist in backups, **no one can read it**. This makes deletion **provable**: you can mathematically prove the data is unrecoverable because the key no longer exists.

---

### Task 7 — Integrity & Tamper-Evidence

**What this task is about:**
Encryption protects **confidentiality** (who can read the data). Hashing protects **integrity** (whether the data was changed). A **hash** is a unique fingerprint of a file — if even one character changes, the hash completely changes. A **hash chain** links each log entry to the previous one, so tampering with any entry is immediately detected.

**Steps performed:**

**Step 1:** Generate a SHA-256 hash of the original file.
```bash
sha256sum record.txt
```
Output: `1b628d33a0af5b85cbb4bcebcf4b4a9c575feef73de172c89feb7c19eb562f8f  record.txt`

**Step 2:** Copy the file, add a character to tamper with it, then compare hashes.
```bash
cp record.txt tampered.txt; echo 'x' >> tampered.txt
sha256sum record.txt tampered.txt
```

**Step 3:** Build a hash chain (tamper-evident log).
```bash
PREV=0
for line in 'login ok' 'file read' 'export data'; do
  PREV=$(echo -n "$PREV$line" | sha256sum | cut -d' ' -f1)
  echo "$line | $PREV"
done
```

**Evidence — Task 7 (Integrity & Tamper-Evidence):**

![Task 7 — Integrity & Tamper-Evidence](Task%207%20—%20Integrity%20&%20Tamper-Evidence.png)

**Result:**
| File | SHA-256 Hash |
|---|---|
| `record.txt` | `1b628d33a0af5b85cbb4bcebcf4b4a9c575feef73de172c89feb7c19eb562f8f` |
| `tampered.txt` | `1a3065e781465f4f0e8166f4f42bb0350449a906c65780c9d99ae26c2d26f553` |

The two hashes are **completely different** — confirming that even a tiny change is detected. The hash chain output:

| Log Entry | Chained Hash |
|---|---|
| `login ok` | `573f9af26d45d395a1089ef5fec4d50ccddc17c0ea4269c2c91d90929a820053` |
| `file read` | `6c3adc61ece69412b338e43d761435e95dbfc948253f8f600087b0a4c5ad2d3d` |
| `export data` | `e1470ccfaf43dcab3c17d5710dc9eacbb7ac65c9f522ca98c2c503431b32da68` |

---

**📝 Short-Answer Question (from Task 7):**

> **Q5: How does a hash chain make a log tamper-evident?**

**Answer:**
In a hash chain, each log entry includes the **hash of the previous entry** plus the new content. This means:
- Every entry depends on all entries before it.
- If an attacker changes one entry (e.g., deletes a "file read" log), the hash of that entry changes.
- This causes all hashes after it to also change.
- Anyone can re-compute the chain and immediately notice the mismatch.

This is exactly how blockchain and audit logs work — it makes tampering **detectable and provable**.

---

## Verification Commands

The following commands were run to verify all completed tasks:

```bash
# List all KMS keys (shows both Tenant A and Tenant B keys were created)
aws --endpoint-url=http://localhost:4566 kms list-keys

# Verify RSA digital signature
openssl dgst -sha256 -verify public.pem -signature record.sig record.txt
```

**Evidence — Verification Commands:**

![Verification Command](Verification%20Command.png)

**Result:**
- `kms list-keys` returned **two keys**: Key A (`99831018-7895-484e-947b-d79cf9bf923c`) and Key B (`8a1fc61f-1a96-40df-9315-91f5ab28a797`) — confirming both tenant keys were created.
- `openssl dgst -sha256 -verify` returned `Verified OK` — confirming the digital signature from Task 2 is still valid.

---

## Short-Answer Questions (Summary)

### Q1 — Compare symmetric and asymmetric encryption: speed, key distribution, and typical use.

| | Symmetric (AES) | Asymmetric (RSA) |
|---|---|---|
| **Speed** | Very fast | Slow |
| **Keys** | One shared key (same for encrypt & decrypt) | Two keys: public (encrypt) + private (decrypt) |
| **Key distribution problem** | Hard — must share the key securely | No problem — public key can be shared openly |
| **Typical use** | Encrypting large files or databases (data at rest) | Key exchange, digital signatures, TLS handshake |

**In short:** Symmetric is faster and used for bulk data. Asymmetric is safer for sharing keys and proving identity. In practice, they are **used together** (e.g., TLS uses asymmetric to exchange a symmetric session key).

---

### Q2 — Why is key management described as the weakest link, not the algorithm?

**Answer:**
Modern encryption algorithms like AES-256 are mathematically unbreakable with current technology. The weakness is not the algorithm — it is **how the keys are stored, shared, and protected**.

If the key is:
- Saved in a plain text file → anyone who accesses the file can decrypt everything.
- Hard-coded in source code → attackers who steal the code get the key.
- Not rotated regularly → old compromised keys remain dangerous.

The algorithm can be perfect, but if the key is stolen or mismanaged, all data is exposed. This is why KMS (Key Management Service) exists — to handle keys securely so humans don't make mistakes.

---

### Q3 — Explain envelope encryption and why only the master key needs hardware-grade protection.
*(Answered in Task 5 above)*

---

### Q4 — How does cryptographic erasure achieve provable deletion where overwriting cannot (in the cloud)?
*(Answered in Task 6 above)*

---

### Q5 — How does a hash chain make a log tamper-evident?
*(Answered in Task 7 above)*

---

## Security Best-Practices Checklist

| Security Control | Status |
|---|---|
| ✅ Data encrypted at rest (AES) and decryption verified | Done — Task 1: `MATCH: decryption successful` |
| ✅ Asymmetric keys used correctly (encrypt with public, sign with private) | Done — Task 2: `Verified OK` |
| ✅ Data protected in transit with TLS | Done — Task 3: `curl -k https://localhost:8443/record.txt` returned file content |
| ✅ Envelope encryption used; plaintext data key not left on disk | Done — Task 5: `datakey.bin` and `datakey.b64` were deleted |
| ✅ Per-tenant keys used; cryptographic erasure demonstrated | Done — Task 6: decrypt attempt returned `NotFoundException` |
| ✅ Integrity verified with hashing / hash chain | Done — Task 7: different hashes confirmed, hash chain built |

---

## Challenges Encountered

| Task | Challenge | How It Was Solved |
|---|---|---|
| **Task 1** | First encryption attempt failed with `bad password read` error | The command was re-run and the password was entered correctly at the prompt |
| **Task 3** | The basic `docker run` command with NGINX did not serve HTTPS automatically — nginx was not configured for SSL | A custom `nginx.conf` was created to configure SSL with `listen 443 ssl`, `ssl_certificate`, and `ssl_certificate_key`. The container was then re-launched with the config mounted |
| **Task 3** | The `-v $(pwd)/...` mount syntax had issues (extra quotes) | The command was cleaned up and run again without extra symbols |
| **Task 5** | The `generate-data-key` command returns two values in one line — needed to separate plaintext key and encrypted key | Used `cut -f1` and `cut -f2` to split the output into separate files |
| **Task 6** | After disabling the key, the `kms decrypt` error message referenced the **ciphertext blob** key ID instead of `KEY_A` directly — confirming the lookup is done against the blob metadata | Verified the error was expected (`NotFoundException`) and not a configuration mistake |

---

## Lessons Learned

1. **Symmetric encryption is fast but has a key-sharing problem.** AES-256 is very strong, but the challenge is safely giving the key to the person who needs it. This is why KMS exists.

2. **Asymmetric encryption solves the key-sharing problem.** The public key can be given to anyone — only the private key holder can decrypt. This is the foundation of TLS, HTTPS, and digital signatures.

3. **TLS is essential for any data in transit.** Without TLS, data travelling over the network is readable by anyone on the same network. With TLS, even if the traffic is captured, it is unreadable.

4. **Envelope encryption is the standard in cloud platforms.** It separates the problem: fast local encryption with a data key, and secure key protection with a master key in KMS. This pattern is used by AWS, Azure, and GCP.

5. **Cryptographic erasure is more powerful than file deletion in the cloud.** Because cloud data exists in backups, replicas, and snapshots, you can never be 100% sure deleting a file removes all copies. But if you destroy the key, all copies — everywhere — become permanently unreadable.

6. **Hashing is the foundation of data integrity and audit logs.** A hash chain means every log entry proves the history before it. This is how blockchain, certificate transparency logs, and tamper-evident audit trails work.

7. **Key management is the real security boundary.** The algorithm (AES, RSA) is not the weak point — it is where and how the keys are stored. Keys in KMS with access control are far safer than keys in files.

---

## References

1. Course Lecture — Week 4 (Data Protection); Week 9 (Key Management Patterns). UniKL MIIT · Prof. Dr. Shahrulniza Musa.
2. OpenSSL Documentation — [www.openssl.org/docs](https://www.openssl.org/docs)
3. AWS KMS Concepts (Envelope Encryption) — [docs.aws.amazon.com/kms](https://docs.aws.amazon.com/kms)
4. CSA Security Guidance v5 — Data Security & Encryption. Cloud Security Alliance.
5. LocalStack Documentation — [docs.localstack.cloud](https://docs.localstack.cloud)
6. NGINX SSL/TLS Documentation — [nginx.org/en/docs/http/configuring_https_servers.html](https://nginx.org/en/docs/http/configuring_https_servers.html)

---

*Lab 3 Report — IKB42603 Cloud Computing Security Essentials*
*UniKL MIIT · Prepared by Ahmad Hakim*
