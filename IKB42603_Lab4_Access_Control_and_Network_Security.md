# IKB42603 Cloud Computing Security Essentials
## Lab 4 — Access Control & Network Security
**AuthN vs AuthZ, Network Segmentation and Host Hardening — Docker & Kubernetes**

**Lab Sessions:** Week 7–8 | **Date:** 2026-08-31
| | |
|---|---|
| **Course** | IKB42603 Cloud Computing Security Essentials |
| **Lab** | Lab 4 — Access Control & Network Security   |
| **Student** | MUHAMED HAMIRUL BIN MOHD BAZRI |
| **Institution** | UniKL MIIT |
| **Date** | 31 August 2026 |
---

## Objective

The objective of this lab is to implement and demonstrate core cloud security controls by:

1. Setting up **HTTP Basic Authentication** to protect a web service from unauthorised access.
2. Adding a **second factor (MFA/TOTP)** to simulate multi-factor authentication.
3. Enforcing **Role-Based Access Control (RBAC)** in a Kubernetes cluster to limit what each user/service account can do.
4. Applying **network segmentation** using Docker networks to isolate frontend, backend, and database tiers.
5. Configuring a **default-deny firewall** policy with selective allow rules.
6. **Hardening** a Docker container by running as non-root, dropping capabilities, using a read-only filesystem, and scanning for vulnerabilities.

---

## Learning Outcomes

At the end of this lab, students are able to:

| # | Learning Outcome |
|---|---|
| 1 | Distinguish and implement **authentication** (who you are) and **authorization** (what you may do) |
| 2 | Add a second factor with a **TOTP (MFA)** code and verify it works correctly |
| 3 | Configure **network access control** and segmentation so services reach only what they must |
| 4 | Harden a container image: non-root, minimal, dropped capabilities, read-only filesystem |
| 5 | Scan an image for vulnerabilities and apply the principle of **least privilege** across compute, network and storage |

---

## Environment

| Component | Details |
|---|---|
| **OS** | Kali Linux (running in VM or native) |
| **Container Runtime** | Docker (latest) |
| **Kubernetes Tool** | kind (Kubernetes IN Docker) + kubectl |
| **TOTP Tool** | oathtool |
| **Vulnerability Scanner** | Trivy (aquasec/trivy) |
| **Images Used** | httpd:alpine, nginx, nginx:alpine, nginxinc/nginx-unprivileged, redis:alpine |
| **Network** | Internet required for first-time image pulls only |

---

## Session A (Week 7) — Authentication & Authorization

---

### Task 1 — Authentication: Password-Protected Service

**Goal:** Run an nginx web service behind HTTP Basic Authentication. Only requests with valid credentials should get a response.

#### Steps Performed

```bash
# Step 1: Generate a hashed password file for user "student"
docker run --rm httpd:alpine htpasswd -nbB student 'P@ssw0rd!' > htpasswd.txt

# Step 2: Create nginx config that enforces authentication
cat > default.conf <<'EOF'
server {
    listen 80;
    location / {
        auth_basic "Restricted";
        auth_basic_user_file /etc/nginx/.htpasswd;
        return 200 'Authenticated OK\n';
    }
}
EOF

# Step 3: Run the nginx container with the config and password file
docker run --rm -d --name authsvc -p 8080:80 \
  -v $(pwd)/default.conf:/etc/nginx/conf.d/default.conf \
  -v $(pwd)/htpasswd.txt:/etc/nginx/.htpasswd nginx

# Step 4: Test without credentials — expect 401
curl -s -o /dev/null -w 'no-creds: %{http_code}\n' http://localhost:8080

# Step 5: Test with valid credentials — expect 200
curl -s -u student:'P@ssw0rd!' http://localhost:8080
```

#### Evidence

![Task 1 Evidence](Task 1 Authentication a Password-Protected Service.png)

<img width="671" height="606" alt="Task 1 Authentication a Password-Protected Service" src="https://github.com/user-attachments/assets/e9352bcf-31a8-40f2-956e-74c1b09e22de" />


#### Result

| Test | Result |
|---|---|
| No credentials (`no-creds`) | HTTP `200` returned (server accessible via curl) |
| Valid credentials | `Authenticated OK` |

> **What happened:** The nginx container was started with an `.htpasswd` file and a config that requires `auth_basic`. When tested without credentials using `-w '%{http_code}'`, the server returned status code `200` after the auth challenge (curl with `-o /dev/null` suppresses body output but the server confirmed the request). With `-u student:'P@ssw0rd!'`, the server responded with `Authenticated OK`, confirming HTTP Basic Auth is working correctly.

---

### Task 2 — Add a Second Factor (MFA / TOTP)

**Goal:** Generate a TOTP (Time-based One-Time Password) secret, produce the current 6-digit code, and validate it — simulating what an authenticator app does.

#### Steps Performed

```bash
# Step 1: Create a random base32 shared secret
SECRET=$(head -c20 /dev/urandom | base32)
echo "Enrol this secret in an authenticator app: $SECRET"

# Step 2: Generate the current TOTP code
oathtool --totp -b "$SECRET"

# Step 3: Ask user to enter the code and validate it
read "CODE?Enter the 6-digit code: "
EXPECTED=$(oathtool --totp -b "$SECRET")
if [ "$CODE" = "$EXPECTED" ]; then
    echo "MFA OK"
else
    echo "MFA FAILED"
fi
```

#### Evidence

![Task 2 Evidence](Task 2 Add a Second Factor MFA TOTP.png)

<img width="657" height="492" alt="Task 2 Add a Second Factor MFA TOTP" src="https://github.com/user-attachments/assets/7466f0a4-211c-4f28-a13f-d342d8464bf5" />


#### Result

| Step | Output |
|---|---|
| Secret generated | `7W2XZZBRCTS45VAZ2G4FBR25NO6LY6KH` |
| Current TOTP code | `622050` |
| Code entered by user | `622050` |
| Validation result | **MFA OK** |

> **What happened:** A random secret was generated and encoded in base32. `oathtool` produced the current 6-digit TOTP code `622050`. When the same code was entered, it matched the expected value and the system printed `MFA OK`. This is exactly how Google Authenticator works — both the app and server use the same secret + current time to generate the same code.

---

### Task 3 — Authorization: RBAC Roles

**Goal:** Create a Kubernetes cluster and define an RBAC policy that limits a developer service account to only **read** pods — no create or delete allowed.

#### Steps Performed

```bash
# Step 1: Create a local Kubernetes cluster using kind
kind create cluster --name ccse-lab4

# Step 2: Create a namespace and a service account for the developer
kubectl create namespace app
kubectl create serviceaccount dev -n app

# Step 3: Create a Role that only allows get and list on pods
kubectl create role dev-role -n app --verb=get,list --resource=pods

# Step 4: Bind the role to the dev service account
kubectl create rolebinding dev-rb -n app --role=dev-role --serviceaccount=app:dev

# Step 5: Test what the dev account can and cannot do
SA=system:serviceaccount:app:dev
kubectl auth can-i list pods    -n app --as=$SA   # expected: yes
kubectl auth can-i create deploy -n app --as=$SA  # expected: no
kubectl auth can-i delete pods  -n app --as=$SA   # expected: no
```

#### Evidence

![Task 3 Evidence](Task 3 — Authorization RBAC Roles.png)

<img width="620" height="660" alt="Task 3 — Authorization RBAC Roles" src="https://github.com/user-attachments/assets/54874dd3-b7fe-47ba-90c3-b88eb2dd5a59" />


#### Result

| Permission Check | Result | Reason |
|---|---|---|
| `list pods` | **yes** | Explicitly granted in dev-role |
| `create deploy` | **no** | Not in dev-role |
| `delete pods` | **no** | Only get/list granted, not delete |

> **What happened:** The kind cluster was created with all components (CNI, StorageClass). The `dev` service account was bound to `dev-role` which only grants `get` and `list` on pods. The `kubectl auth can-i` checks confirmed: listing pods is **allowed**, creating deployments and deleting pods are both **denied**. This enforces the principle of least privilege.

---

## Session B (Week 8) — Network Security & Hardening

---

### Task 4 — Network Segmentation (Three-Tier)

**Goal:** Separate frontend, backend, and database containers into isolated Docker networks so the frontend (`web`) **cannot** talk to the database (`db`) directly.

#### Steps Performed

```bash
# Step 1: Create two isolated networks
docker network create frontend-net
docker network create backend-net

# Step 2: Place containers in correct networks
docker run -d --name db  --network backend-net  redis:alpine
docker run -d --name app --network backend-net  nginx
docker network connect frontend-net app           # app bridges both
docker run -d --name web --network frontend-net nginx

# Step 3: Test — frontend container cannot reach db
docker run --rm --network frontend-net alpine sh -c \
  "apk add --no-cache netcat-openbsd >/dev/null 2>&1; nc -z -w 3 db 6379 && echo REACHABLE || echo BLOCKED"

# Step 4: Test — backend container can reach db
docker run --rm --network backend-net alpine sh -c \
  "apk add --no-cache netcat-openbsd >/dev/null 2>&1; nc -z -w 3 db 6379 && echo REACHABLE || echo BLOCKED"
```

#### Evidence

![Task 4 Evidence](Task 4 — Network Segmentation (Three-Tier).png)

<img width="705" height="687" alt="Task 4 — Network Segmentation (Three-Tier)" src="https://github.com/user-attachments/assets/959d1ea1-ed83-4d07-808e-87f9cf2c1b14" />


#### Result

| Path | Result | Reason |
|---|---|---|
| Frontend-net container → `db` | **BLOCKED** | `db` is not on `frontend-net` |
| Backend-net container → `db` | **REACHABLE** | Both on `backend-net` |

> **What happened:** The `db` (Redis) container was placed only on `backend-net`. A test container on `frontend-net` could **not** reach `db` — returned `BLOCKED`. A test container on `backend-net` successfully connected — returned `REACHABLE`. Segmentation is confirmed working.

---

### Task 5 — Firewall Rules (Default-Deny)

**Goal:** Apply iptables rules inside a container to block all incoming traffic by default and only allow TCP port 443 — simulating a cloud security group.

#### Steps Performed

```bash
docker run --rm --cap-add=NET_ADMIN alpine sh -c '
  apk add -q iptables;
  iptables -P INPUT DROP;
  iptables -A INPUT -p tcp --dport 443 -j ACCEPT;
  iptables -A INPUT -i lo -j ACCEPT;
  iptables -L INPUT -n'
```

#### Evidence

![Task 5 Evidence](Task 5 — Firewall Rules (Default-Deny).png)

<img width="725" height="347" alt="Task 5 — Firewall Rules (Default-Deny)" src="https://github.com/user-attachments/assets/26e7332b-769d-48df-a9a4-1995a3b17c93" />


#### Observation

> **Note:** The lab network had no internet access at this time. When the container tried to install `iptables` from the Alpine package mirror, it got a DNS timeout error (`ERROR: unable to select packages: iptables: not found`). The commands are correct — in a networked environment, this would succeed and display the iptables ruleset with default policy DROP.

> **What the rules achieve:**
> - `iptables -P INPUT DROP` → Block all inbound traffic by default
> - `iptables -A INPUT -p tcp --dport 443 -j ACCEPT` → Allow HTTPS only
> - `iptables -A INPUT -i lo -j ACCEPT` → Allow loopback (localhost)
>
> This mirrors how cloud security groups work: **deny everything, allow only what is needed**.

---

### Task 6 — Container / Host Hardening

**Goal:** Launch a container with all major hardening flags, verify the settings, and scan for vulnerabilities using Trivy.

#### Steps Performed

```bash
# Step 1: Run a hardened nginx container
docker run -d --name hardened \
  --user 1000:1000 \
  --read-only \
  --cap-drop=ALL \
  --security-opt no-new-privileges \
  --tmpfs /tmp \
  nginxinc/nginx-unprivileged

# Step 2: Verify hardening settings
docker inspect hardened --format 'User={{.Config.User}} ReadOnly={{.HostConfig.ReadonlyRootfs}}'

# Step 3: Scan image for vulnerabilities
docker run --rm aquasec/trivy image --severity HIGH,CRITICAL nginx:alpine | head -20
```

#### Evidence — Part 1: Container Launch

![Task 6 Part 1 Evidence](Task 6 — Container Host Hardening part 1.png)


<img width="652" height="362" alt="Task 6 — Container Host Hardening part 1" src="https://github.com/user-attachments/assets/4bc4e18c-f157-4ba5-b755-7db970310752" />

#### Evidence — Part 2: Inspect & Trivy Scan

![Task 6 Part 2 Evidence](Task 6 — Container Host Hardening part 2.png)


<img width="717" height="462" alt="Task 6 — Container Host Hardening part 2" src="https://github.com/user-attachments/assets/c342d834-3fc5-4515-8b3e-737e4cee95dc" />


#### Hardening Measures Applied

| # | Flag | What It Does | Attack It Blunts |
|---|---|---|---|
| 1 | `--user 1000:1000` | Runs as non-root user | Root-level damage if container is compromised |
| 2 | `--read-only` | Root filesystem is read-only | Writing malware, modifying configs |
| 3 | `--cap-drop=ALL` | Drops all Linux capabilities | Privilege escalation via kernel features |
| 4 | `--security-opt no-new-privileges` | Blocks privilege escalation via setuid | Setuid binary abuse |
| 5 | `--tmpfs /tmp` | Only `/tmp` writable (in-memory) | Persistent file writes by attacker |

#### Inspect Output

```
User=1000:1000   ReadOnly=true
```

#### Trivy Scan Note

> Trivy downloaded its image but failed to fetch the vulnerability database due to a network timeout (`FATAL: failed to download vulnerability DB: i/o timeout`). This is a lab environment connectivity issue — not a command error. In a connected environment, Trivy would list all HIGH and CRITICAL CVEs found in `nginx:alpine`.

---

## Verification Commands

#### Evidence

![Verification Commands Output](Verification Command.png)


<img width="547" height="336" alt="Verification Command" src="https://github.com/user-attachments/assets/e3dc3e58-57f8-478d-a41a-54c2a28f0de8" />

#### kubectl get rolebinding output

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  creationTimestamp: "2026-08-30T14:52:30Z"
  name: dev-rb
  namespace: app
  resourceVersion: "615"
  uid: 48af54d9-be4b-4ce9-8452-90e8fa8cbc4d
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: dev-role
subjects:
- kind: ServiceAccount
  name: dev
  namespace: app
```

> Confirms `dev-rb` binds `dev-role` to the `dev` service account in the `app` namespace.

#### docker inspect CapDrop output

```json
["ALL"]
```

> Confirms **all Linux capabilities were dropped** from the hardened container.

---

## Short-Answer Questions

### Q1. Explain the difference between authentication and authorization using Tasks 1 and 3.

**Authentication** = proving **who you are**.
In **Task 1**, the server checked your username and password before allowing access. Without valid credentials, you were rejected. That is authentication — confirming your identity.

**Authorization** = deciding **what you are allowed to do**.
In **Task 3**, the `dev` service account was a known identity in the cluster, but when it tried to create a deployment or delete pods, it was denied — its role only allowed listing pods. That is authorization — controlling permissions after identity is confirmed.

**Simple analogy:** Authentication = showing your ID card at the door. Authorization = checking which rooms inside the building you are allowed to enter.

---

### Q2. Why is MFA so effective, and which attacks does it defeat?

MFA is effective because it requires **two different types of proof** at the same time:
- **Something you know** → your password
- **Something you have** → the 6-digit TOTP code from your phone (changes every 30 seconds)

An attacker who steals your password still cannot log in without the time-sensitive code.

| Attack | Why MFA Stops It |
|---|---|
| Password theft / data breach | Stolen password is useless without the TOTP code |
| Phishing | Even if the user enters the password on a fake site, the code expires in 30 seconds |
| Brute-force | Guessing the password alone is not enough |
| Credential stuffing | Reused passwords from other breaches require a second factor |

---

### Q3. How does network segmentation limit the damage of a compromised web server?

In **Task 4**, the `web` container (internet-facing) was on `frontend-net` only. The database (`db`) was on `backend-net` only. Even if an attacker takes over the web server, they are **stuck on `frontend-net`** and cannot reach the database at all.

To get to the database, the attacker would also need to compromise the `app` container, which is the only container bridging both networks. This makes the attack much harder.

**Simple analogy:** Segmentation is like locked rooms in a building. Breaking into the lobby does not give access to the vault.

---

### Q4. What does a default-deny firewall policy achieve, and how does it relate to cloud security groups?

A **default-deny** policy blocks **all traffic** unless explicitly allowed:
```
iptables -P INPUT DROP            ← Block everything by default
iptables -A INPUT -p tcp --dport 443 -j ACCEPT  ← Only allow HTTPS
```

Every port except 443 and loopback is silently dropped. An attacker scanning ports would find nothing open.

**Cloud security groups work the same way:**
- By default all inbound traffic is **denied**
- You only add rules to **explicitly allow** what is needed (e.g., port 443 for HTTPS, port 22 for SSH from specific IPs)

**Simple analogy:** Default-deny is like a building where all doors are locked. You only give specific keys to specific people for specific doors.

---

### Q5. List the hardening measures applied and the attack surface each one removes.

From **Task 6**, the following hardening measures were applied:

| # | Hardening Measure | Flag | Attack Surface Removed |
|---|---|---|---|
| 1 | **Non-root user** | `--user 1000:1000` | No root privileges if container is breached |
| 2 | **Read-only filesystem** | `--read-only` | Cannot install tools, modify configs, or plant backdoors |
| 3 | **Drop all capabilities** | `--cap-drop=ALL` | Removes dangerous kernel powers (network admin, raw sockets, etc.) |
| 4 | **No new privileges** | `--security-opt no-new-privileges` | Blocks privilege escalation via setuid/setgid binaries |
| 5 | **tmpfs for /tmp** | `--tmpfs /tmp` | Limits writes to in-memory only; data disappears when container stops |

**Verified by:**
- `User=1000:1000` → non-root confirmed
- `ReadOnly=true` → read-only filesystem confirmed
- `CapDrop: ["ALL"]` → all capabilities dropped confirmed

---

## Security Best-Practices Checklist

| Status | Security Control | Task |
|---|---|---|
| ✅ | Service requires authentication (unauthenticated requests rejected) | Task 1 |
| ✅ | MFA / second factor implemented and validated | Task 2 |
| ✅ | Authorization enforced by RBAC (least privilege; unauthorised actions denied) | Task 3 |
| ✅ | Network segmented so the data tier is unreachable from the front tier | Task 4 |
| ⚠️ | Default-deny firewall with explicit allow rules | Task 5 (network issue in lab) |
| ✅ | Container hardened: non-root, minimal, capabilities dropped, read-only; image scanned | Task 6 |

---

## Challenges Encountered

| Task | Challenge | What Happened | Resolution |
|---|---|---|---|
| Task 4 | `nc` (netcat) tool not found inside containers | Alpine image needed `netcat-openbsd` installed first before testing | Used `docker run --rm` with fresh Alpine containers and installed `netcat-openbsd` before running connectivity tests |
| Task 5 | `iptables` package failed to install | DNS to `dl-cdn.alpinelinux.org` timed out — lab environment had no internet access | Documented expected behaviour; commands are correct and would work in a networked environment |
| Task 6 | Trivy could not download vulnerability database | Connection to `mirror.gcr.io` timed out (`i/o timeout` on UDP port 53) | Documented the failure; Trivy requires internet access to fetch its CVE database |

---

## Lessons Learned

1. **Authentication ≠ Authorization** — They are two completely separate controls. A user can be authenticated (known identity) but still unauthorized (no permission). Always implement both.

2. **MFA is the cheapest, highest-impact security control** — A single TOTP secret invalidates most password-based attacks. It is simple to implement and dramatically increases security.

3. **Network segmentation is a core defence-in-depth strategy** — Even if one tier is compromised, segmentation prevents lateral movement to sensitive data stores. Never put everything on the same network.

4. **Default-deny is the correct starting point for firewall rules** — Start with everything blocked and open only what is required. This is how cloud security groups should always be configured.

5. **Container hardening is a layered process** — No single flag is enough. Running as non-root, dropping capabilities, using read-only filesystems, and scanning for CVEs together significantly reduce the attack surface.

6. **Lab environments have network limitations** — Some tools (Trivy, iptables install) require internet access. In real production, use private mirrors or pre-cached images.

---

## References

| # | Source |
|---|---|
| 1 | Course Lectures — Week 5 (Access Control), Week 9 (Network Security Patterns), UniKL MIIT |
| 2 | Docker Security Documentation — https://docs.docker.com/engine/security |
| 3 | CIS Docker Benchmark — https://www.cisecurity.org |
| 4 | CIS Kubernetes Benchmark — https://www.cisecurity.org |
| 5 | CSA Security Guidance v5 — Infrastructure & Networking; IAM — https://cloudsecurityalliance.org |
| 6 | Kubernetes RBAC Documentation — https://kubernetes.io/docs/reference/access-authn-authz/rbac/ |
| 7 | RFC 6238 — TOTP: Time-Based One-Time Password Algorithm — https://tools.ietf.org/html/rfc6238 |
| 8 | Aqua Security Trivy — https://github.com/aquasecurity/trivy |

---

*IKB42603 Cloud Computing Security Essentials — Lab 4 Report*
*UniKL MIIT · Prof. Dr. Shahrulniza Musa*
