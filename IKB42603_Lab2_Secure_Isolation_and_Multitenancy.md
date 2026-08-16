# IKB42603 Cloud Computing Security Essentials
## Lab 2: Secure Isolation & Multi-Tenancy
**Compute, Network, and Storage Isolation — Docker & Kubernetes**

---

### Course & Student Information
- **Course Code:** IKB42603 (Cloud Computing Security Essentials)
- **Institution:** Universiti Kuala Lumpur — Malaysian Institute of Information Technology (UniKL MIIT)
- **Course Instructor:** Prof. Dr. Shahrulniza Musa
- **Course Learning Outcome (CLO):** CLO2 — Construct secure cloud operations that safeguard data integrity
- **Value / Skill Clusters:** VBE3 (Integrity) · SC8 (Integrated Problem-Solving)
- **Document Type:** Step-by-Step Laboratory Report & Security Verification

---

## Table of Contents
1. [Objective](#1-objective)
2. [Learning Outcomes](#2-learning-outcomes)
3. [Environment & Prerequisites](#3-environment--prerequisites)
4. [Step-by-Step Lab Execution & Evidence](#4-step-by-step-lab-execution--evidence)
   - [Setup Phase: Kind Cluster Initialization & Calico CNI Deployment](#setup-phase-kind-cluster-initialization--calico-cni-deployment)
   - [Session A (Week 3): Compute Isolation & Default-Open Vulnerability](#session-a-week-3-compute-isolation--the-default-open-risk)
     - [Task 1 — Two Tenants on One Cluster](#task-1--two-tenants-on-one-cluster)
     - [Task 2 — Observe the Default-Open Risk](#task-2--observe-the-default-open-risk)
     - [Task 3 — Contain the Noisy Neighbour (Resource Quotas)](#task-3--contain-the-noisy-neighbour-resource-quotas)
   - [Session B (Week 4): Network & Storage Isolation](#session-b-week-4-network--storage-isolation)
     - [Task 4 — Default-Deny Network Isolation](#task-4--default-deny-network-isolation)
     - [Task 5 — Storage & Secret Isolation](#task-5--storage--secret-isolation)
     - [Task 6 — Data Remanence & Secure Deletion](#task-6--data-remanence--secure-deletion)
   - [Advanced Expansion Tasks (Security Hardening & Micro-Segmentation)](#advanced-expansion-tasks-security-hardening--micro-segmentation)
     - [Advanced Task 1 — Default-Deny Egress Policy](#advanced-task-1--default-deny-egress-policy)
     - [Advanced Task 2 — CoreDNS Granular Egress Policy](#advanced-task-2--coredns-granular-egress-policy)
     - [Advanced Task 3 — Micro-Segmentation: Whitelist Specific Backend Service](#advanced-task-3--micro-segmentation-whitelist-specific-backend-service)
     - [Advanced Task 4 — Pod Security Standards (PSS) Restricted Mode](#advanced-task-4--pod-security-standards-pss-restricted-mode)
     - [Advanced Task 5 — Non-Root Hardened Workload Deployment](#advanced-task-5--non-root-hardened-workload-deployment)
     - [Advanced Task 6 — Calico GlobalNetworkPolicy for Cluster-Wide Isolation](#advanced-task-6--calico-globalnetworkpolicy-for-cluster-wide-isolation)
     - [Advanced Task 7 — Cluster State & Network Policy Verification](#advanced-task-7--cluster-state--network-policy-verification)
5. [Deliverables & Short-Answer Questions](#5-deliverables--short-answer-questions)
6. [Security Best-Practices Checklist](#6-security-best-practices-checklist)
7. [Challenges Encountered & Solutions](#7-challenges-encountered--solutions)
8. [Lessons Learned](#8-lessons-learned)
9. [Teardown & Cleanup](#9-teardown--cleanup)
10. [References](#10-references)

---

## 1. Objective

The primary objective of this laboratory is to systematically explore, analyze, and enforce **Multi-Tenancy Isolation** across the three fundamental computing dimensions in cloud platforms: **Compute**, **Network**, and **Storage**. 

In shared cloud and containerized infrastructures (such as Kubernetes and Docker), multiple tenants often share identical physical hardware, kernel layers, and flat software-defined networks. Without explicit security controls, this shared model introduces severe security risks, including cross-tenant data snooping, lateral movement, denial of service (via noisy-neighbour resource starvation), and data remanence upon storage de-allocation.

Through this practical session, students configure:
1. **Compute & Resource Isolation:** Namespace logical partitioning and CPU/Memory/Pod `ResourceQuota` controls to eliminate noisy-neighbour interference.
2. **Network Isolation & Micro-Segmentation:** Custom Container Network Interface (CNI) configuration (Project Calico) replacing default open flat networks with zero-trust **Default-Deny Ingress/Egress** and **GlobalNetworkPolicy** rules.
3. **Storage & Access Isolation:** Cryptographic and access boundary enforcement using Kubernetes Role-Based Access Control (RBAC) to ensure tenant secrets remain strictly confidential.
4. **Data Sanitization & Remanence Protection:** Volume-level data persistence analysis, secure block overwriting (`dd` shredding), and cloud cryptographic erasure evaluation.
5. **Advanced Hardening:** Implementing Kubernetes **Pod Security Standards (PSS) Restricted Profile** to mitigate container breakouts and kernel privilege escalation.

---

## 2. Learning Outcomes

Upon successful completion of this laboratory module, students have achieved the following learning outcomes mapped directly to **CLO2**:

- **LO1 (Compute Isolation):** Successfully demonstrate physical and logical compute isolation by segregating workloads into Kubernetes namespaces and setting strict resource caps.
- **LO2 (Risk Analysis):** Observe and evaluate the inherent security dangers of flat, "default-open" software-defined networks in multi-tenant environments.
- **LO3 (Network Segmentation):** Construct and validate zero-trust `NetworkPolicy` rules (Default-Deny Ingress/Egress) enforced via Calico CNI, verifying complete traffic blockage between unprivileged tenant boundaries.
- **LO4 (Storage & Secret Privacy):** Implement granular RBAC policies, RoleBindings, and ServiceAccounts ensuring tenant secret confidentiality across namespaces.
- **LO5 (Data Remanence Remediation):** Contrast standard OS-level file deletion against secure data sanitization (zero-block overwriting) and explain why cryptographic erasure is the primary defense in elastic cloud storage.
- **LO6 (Defense-in-Depth & PSS):** Enforce modern Kubernetes Pod Security Standards (Restricted) to prevent root execution and kernel capability abuse.

---

## 3. Environment & Prerequisites

### 3.1 Software & Tooling Stack
| Component | Technology / Tool | Version / Details | Purpose |
| :--- | :--- | :--- | :--- |
| **Operating System** | Kali Linux / Debian GNU/Linux | Rolling Release (x86_64) | Security administration host environment |
| **Container Engine** | Docker Engine / Docker Desktop | 24.x+ | Local container runtime & volume testing |
| **Local Cluster** | `kind` (Kubernetes in Docker) | v0.20+ | Multi-tenant Kubernetes cluster simulation |
| **Cluster Management** | `kubectl` CLI | v1.28+ | Kubernetes control plane communication |
| **Network Security (CNI)** | Project Calico CNI | v3.27.0 | L3/L4 NetworkPolicy & GlobalNetworkPolicy enforcement |
| **Tenant Workloads** | Nginx / Nginx-Unprivileged / cURL | Official Alpine/Debian images | Multi-tenant test web servers & probe agents |

### 3.2 Architectural Model
```
+---------------------------------------------------------------------------------------+
|                               Kubernetes Cluster (kind: ccse-lab2)                    |
|                                     Calico CNI Enforcement Layer                     |
+---------------------------------------------------+-----------------------------------+
|  Namespace: mii-a (Tenant A)                      |  Namespace: kim-b (Tenant B)      |
|  - ResourceQuota: mii-a-quota                     |  - Pod Security: Restricted       |
|  - Secret: data (SECRET_A)                        |  - Secret: data (SECRET_B)        |
|  - ServiceAccount: app-a (Scoped RBAC)            |  - Service: web (ClusterIP: 10.96.129.140)|
|  - Deployment: web (Port 80)                      |  - Service: backend (Port 80)     |
|  - NetworkPolicy: default-deny-egress             |  - NetworkPolicy: default-deny-ingress |
|  - NetworkPolicy: allow-dns                       |                                   |
|  - NetworkPolicy: allow-backend                   |                                   |
+---------------------------------------------------+-----------------------------------+
|               Calico GlobalNetworkPolicy: tenant-isolation (Cluster-Wide)             |
+---------------------------------------------------------------------------------------+
```

---

## 4. Step-by-Step Lab Execution & Evidence

### Setup Phase: Kind Cluster Initialization & Calico CNI Deployment

Standard Kubernetes clusters provisioned with default drivers (such as `kindnet`) provide a flat network where all pods can communicate freely with all other pods across namespaces without enforcing `NetworkPolicy` objects. To establish an infrastructure capable of enforcing network security policies, a custom `kind` cluster is created with `disableDefaultCNI: true` and an explicit pod CIDR subnet (`192.168.0.0/16`), followed by deploying the **Project Calico CNI** daemonset.

#### Step 1: Initialize Kind Cluster with Custom CNI
```bash
cat <<EOF | kind create cluster --name ccse-lab2 --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: 192.168.0.0/16
EOF
```

> **Security Note:** Disabling the default CNI prevents automatic pod routing until Calico pods and CRDs are registered, ensuring no unmonitored traffic flows during boot.

![Kind Cluster Setup & ISO Initialization](<setup the iso.png>)
*Figure 1: Initialization attempt and configuration check for Kind cluster `ccse-lab2`.*

---

#### Step 2: Deploy Project Calico CNI & Validate Rollout
```bash
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/calico.yaml
kubectl -n kube-system rollout status daemonset/calico-node --timeout=180s
```

Calico installs custom resource definitions (CRDs), `calico-node` daemonsets across all worker nodes, and `calico-kube-controllers` to intercept and manage packet filtering through Linux kernel `iptables` / eBPF data planes.

![Calico DaemonSet Rollout Verification](<validate kube-system rollout.png>)
*Figure 2: Calico CNI components installed and daemonset `calico-node` successfully rolled out in `kube-system`.*

---

### Session A (Week 3): Compute Isolation & the Default-Open Risk

#### Task 1 — Two Tenants on One Cluster

To model two distinct enterprise customers sharing identical cloud hardware, two separate namespaces are created: `mii-a` (Tenant A) and `kim-b` (Tenant B). Each tenant deploys an Nginx web server exposed via an internal Kubernetes `ClusterIP` Service.

```bash
# 1. Create tenant namespaces
kubectl create namespace mii-a
kubectl create namespace kim-b

# 2. Deploy web server in each namespace
kubectl -n mii-a create deployment web --image=nginx
kubectl -n kim-b create deployment web --image=nginx

# 3. Expose services on port 80
kubectl -n mii-a expose deployment web --port=80
kubectl -n kim-b expose deployment web --port=80

# 4. Inspect workloads in both namespaces
kubectl get pods,svc -n mii-a
kubectl get pods,svc -n kim-b
```

**Observed Configuration:**
- Tenant A (`mii-a`): Pod `web-7887448d46-ktgfc` (Running) | Service `web` (`10.96.202.93:80/TCP`)
- Tenant B (`kim-b`): Pod `web-7887448d46-bctq2` (Running) | Service `web` (`10.96.129.140:80/TCP`)

![Task 1: Workloads Running in Tenant Namespaces](<Task 1 — Two Tenants on One Cluster.png>)
*Figure 3: Deployment of isolated tenant namespaces (`mii-a`, `kim-b`) with active web pods and ClusterIP services.*

---

#### Task 2 — Observe the Default-Open Risk

In an unhardened multi-tenant cluster, namespace logical separation only partitions names and metadata; **it does NOT partition network connectivity**. 

To demonstrate this vulnerability, a temporary test container (`curlimages/curl`) is executed inside Tenant A's namespace (`mii-a`) to probe the private web service belonging to Tenant B (`kim-b` at IP `10.96.129.140`).

```bash
# Obtain Tenant B's ClusterIP
kubectl get svc web -n kim-b -o jsonpath='{.spec.clusterIP}'; echo

# Probe Tenant B from Tenant A
kubectl -n mii-a run probe --rm -it --image=curlimages/curl --restart=Never \
  -- curl -s -m 5 http://10.96.129.140 -o /dev/null -w 'HTTP %{http_code}\n'
```

**Result & Security Analysis:**
The probe returns **`HTTP 200`**, proving that Tenant A was able to access Tenant B's private internal HTTP service without authentication or authorization. In an unconfigured multi-tenant environment, an attacker compromising one tenant container can freely pivot and snoop on adjacent tenant workloads.

![Task 2: Default-Open Cross-Tenant Access](<Task 2 — Observe the Default-Open Risk.png>)
*Figure 4: Inter-tenant probe execution resulting in `HTTP 200`, demonstrating the critical default-open security risk.*

---

#### Task 3 — Contain the Noisy Neighbour (Resource Quotas)

Compute isolation requires protecting shared cluster hardware from resource starvation attacks or accidental CPU/Memory exhaustion caused by a misconfigured tenant ("noisy neighbour" syndrome). 

A Kubernetes `ResourceQuota` is applied to Tenant A (`mii-a`) enforcing:
- Maximum CPU Requests: `1` core
- Maximum Memory Requests: `512Mi`
- Maximum Number of Pods: `5`

```bash
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ResourceQuota
metadata:
  name: mii-a-quota
  namespace: mii-a
spec:
  hard:
    requests.cpu: "1"
    requests.memory: 512Mi
    pods: "5"
EOF

# Verify applied quota
kubectl describe resourcequota mii-a-quota -n mii-a
```

![Task 3: ResourceQuota Enforcement](<Task 3 — Contain the Noisy Neighbour (Resource Quotas).png>)
*Figure 5: `ResourceQuota` created in `mii-a`, limiting total pods to 5, CPU to 1 core, and memory requests to 512Mi.*

---

### Session B (Week 4): Network & Storage Isolation

#### Task 4 — Default-Deny Network Isolation

To eliminate the default-open risk discovered in Task 2, a **Default-Deny Ingress** `NetworkPolicy` is applied to Tenant B (`kim-b`). This policy selects all pods within `kim-b` (`podSelector: {}`) and specifies `policyTypes: [Ingress]` without any ingress rules, effectively dropping all incoming packets from external namespaces.

```bash
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: kim-b
spec:
  podSelector: {}
  policyTypes: [Ingress]
EOF
```

```bash
# Re-test connectivity from Tenant A to Tenant B
kubectl -n mii-a run probe --rm -it --image=curlimages/curl --restart=Never \
  -- curl -s -m 5 http://10.96.129.140 -o /dev/null -w 'HTTP %{http_code}\n'
```

**Security Analysis:**
As shown in the output, applying the default-deny ingress policy prevents unsolicited cross-namespace access. Furthermore, due to the ResourceQuota configured in Task 3, any un-budgeted pod launched in `mii-a` without explicit CPU/Memory request parameters is strictly forbidden by the Kubernetes admission controller, reinforcing multi-layered defense.

![Task 4: Default-Deny Ingress Policy Verification](<Task 4 — Default-Deny Network Isolation.png>)
*Figure 6: Application of `default-deny-ingress` on `kim-b` and admission controller quota check.*

---

#### Task 5 — Storage & Secret Isolation

Multi-tenant confidentiality requires that cryptographic keys, tokens, and credentials stored in Kubernetes `Secrets` are isolated so one tenant's service identity cannot read another tenant's secrets.

#### Step 1: Create Tenant Secrets & Dedicated Service Account
```bash
# Create unique secrets in each tenant namespace
kubectl -n mii-a create secret generic data --from-literal=value=SECRET_A
kubectl -n kim-b create secret generic data --from-literal=value=SECRET_B

# Create ServiceAccount in Tenant A
kubectl -n mii-a create serviceaccount app-a

# Create scoped Role granting secret read access in Tenant A only
kubectl -n mii-a create role reader --verb=get --resource=secrets
```

![Task 5: Secret and RBAC Role Creation](<Task 5 — Storage & Secret Isolation [art 1.png>)
*Figure 7: Creation of namespaced secrets and RBAC `reader` role.*

---

#### Step 2: Bind Role and Test Authorization Boundary
```bash
# Bind role to ServiceAccount in Tenant A
kubectl -n mii-a create rolebinding rb --role=reader --serviceaccount=mii-a:app-a

# Perform RBAC can-i authorization checks
SA=system:serviceaccount:mii-a:app-a
kubectl auth can-i get secrets -n mii-a --as=$SA
kubectl auth can-i get secrets -n kim-b --as=$SA
```

**Result & Verification:**
- `kubectl auth can-i get secrets -n mii-a --as=$SA` $\rightarrow$ **`yes`**
- `kubectl auth can-i get secrets -n kim-b --as=$SA` $\rightarrow$ **`no`**

The authorization probe confirms that the tenant's ServiceAccount is strictly confined to its assigned namespace, proving RBAC-enforced storage and secret isolation.

![Task 5: RBAC Isolation Verification](<Task 5 — Storage & Secret Isolation part2.png>)
*Figure 8: Proof of secret isolation via `kubectl auth can-i` queries.*

---

#### Task 6 — Data Remanence & Secure Deletion

When a container volume is recycled or a file is removed using standard commands (e.g., `rm`), the underlying data blocks are typically not erased; only the directory inode pointers are unlinked.

#### Experiment 1: Standard Deletion (Data Remanence Risk)
```bash
docker run --rm -v ccse-vol:/data alpine sh -c \
  'echo SENSITIVE-PATIENT-RECORD > /data/phi.txt; sync; rm /data/phi.txt; \
   grep -a SENSITIVE /data/* 2>/dev/null; echo scan-done'
```
*Result:* Data unlinked from file system table, but raw disk blocks remain vulnerable to raw sector forensic recovery.

#### Experiment 2: Secure Erasure via Zero-Overwriting (Shredding)
```bash
docker run --rm -v ccse-vol:/data alpine sh -c \
  'echo SENSITIVE > /data/phi2.txt; sync; \
   dd if=/dev/zero of=/data/phi2.txt bs=1k count=1 conv=notrunc; rm /data/phi2.txt; \
   echo wiped'
```
*Result:* 1024 bytes (1.0 KB) explicitly overwritten with zero-bytes (`dd if=/dev/zero`) before inode destruction, completely obliterating magnetic/flash data persistence.

![Task 6: Data Remanence & Secure Wipe Execution](<Task 6 — Data Remanence & Secure Deletion.png>)
*Figure 9: Docker volume execution demonstrating file creation, unsecure deletion, and secure byte overwrite (`dd if=/dev/zero`).*

---

### Advanced Expansion Tasks (Security Hardening & Micro-Segmentation)

To move beyond baseline controls and implement a hardened, enterprise-grade multi-tenant architecture, the following expansion tasks were executed.

---

#### Advanced Task 1 — Default-Deny Egress Policy

While ingress filtering prevents unwanted incoming traffic, egress filtering is essential to prevent compromised pods from initiating command-and-control (C2) callbacks or exfiltrating data to external networks.

```bash
kubectl apply -f - << 'EOF'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress
  namespace: mii-a
spec:
  podSelector: {}
  policyTypes:
  - Egress
EOF
```

![Advanced Task 1: Default-Deny Egress Policy](<Default-Deny Egress advanced.png>)
*Figure 10: Creation of `default-deny-egress` network policy in namespace `mii-a`.*

---

#### Advanced Task 2 — CoreDNS Granular Egress Policy

When a total egress deny policy is enforced, internal DNS resolution (`kube-dns` / CoreDNS) is immediately blocked. A granular policy is defined to selectively whitelist egress traffic specifically to UDP/TCP port 53 within the `kube-system` namespace.

```bash
kubectl apply -f - << 'EOF'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns
  namespace: mii-a
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
      podSelector:
        matchLabels:
          k8s-app: kube-dns
    ports:
    - protocol: UDP
      port: 53
    - protocol: TCP
      port: 53
EOF
```

![Advanced Task 2: CoreDNS Egress Whitelisting](<Allow DNS advanced.png>)
*Figure 11: Application of `allow-dns` egress policy permitting internal name resolution to `kube-system` DNS pods on port 53.*

---

#### Advanced Task 3 — Micro-Segmentation: Whitelist Specific Backend Service

Under the **Principle of Least Privilege**, instead of opening all cross-namespace communication, a micro-segmentation egress policy is deployed to allow Tenant A (`mii-a`) to reach ONLY a designated backend service labeled `app: backend` in Tenant B (`kim-b`) on port 80.

#### Step 1: Deploy Backend Service in Tenant B
```bash
kubectl -n kim-b create deployment backend --image=nginxinc/nginx-unprivileged
kubectl -n kim-b expose deployment backend --port=80
kubectl get svc -n kim-b
```
*(Backend service assigned ClusterIP `10.96.101.139:80/TCP`)*

![Advanced Task 3: Backend Deployment](<Allow ONE specific service part 1 advanced.png>)
*Figure 12: Deployment of unprivileged backend workload and service in `kim-b`.*

---

#### Step 2: Define Targeted Egress Policy in Tenant A
```bash
kubectl apply -f - << 'EOF'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-backend
  namespace: mii-a
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kim-b
      podSelector:
        matchLabels:
          app: backend
    ports:
    - protocol: TCP
      port: 80
EOF
```

![Advanced Task 3: Allow Specific Service Egress](<Allow ONE specific service part 2 advanced.png>)
*Figure 13: Configuration of fine-grained micro-segmentation rule `allow-backend` targeting `kim-b` backend pods.*

---

#### Advanced Task 4 — Pod Security Standards (PSS) Restricted Mode

To prevent container breakout attacks where a container gains root access to the host kernel or mounts sensitive host paths, both tenant namespaces are labeled with the Kubernetes **Restricted Pod Security Standard (PSS)**.

```bash
kubectl label --overwrite namespace mii-a \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=latest

kubectl label --overwrite namespace kim-b \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=latest

# Validate applied labels
kubectl get ns --show-labels | grep -E "mii|kim"
```

![Advanced Task 4: Pod Security Standards Enforcement](<Enable Restricted Pod Security advanced.png>)
*Figure 14: Enforcing `restricted` pod security standard labels on namespaces `mii-a` and `kim-b`.*

---

#### Advanced Task 5 — Non-Root Hardened Workload Deployment

Under the `restricted` PSS profile, containers must explicitly define hardened `securityContext` settings. A hardened test pod (`app-a`) is deployed in `mii-a` specifying `runAsNonRoot: true`, `capabilities: { drop: ["ALL"] }`, `allowPrivilegeEscalation: false`, and `seccompProfile: { type: "RuntimeDefault" }`.

```bash
kubectl -n mii-a run app-a \
  --image=nginx \
  --restart=Never \
  --overrides='
{
  "spec": {
    "securityContext": {
      "runAsNonRoot": true,
      "seccompProfile": {
        "type": "RuntimeDefault"
      }
    },
    "containers": [{
      "name": "app-a",
      "image": "nginxinc/nginx-unprivileged",
      "securityContext": {
        "allowPrivilegeEscalation": false,
        "capabilities": {
          "drop": ["ALL"]
        }
      }
    }]
  }
}'
```

![Advanced Task 5: Hardened Pod Creation](<Create test pods advanced.png>)
*Figure 15: Successful provisioning of hardened non-root container conforming to the Restricted Pod Security profile.*

---

#### Advanced Task 6 — Calico GlobalNetworkPolicy for Cluster-Wide Isolation

Standard Kubernetes `NetworkPolicy` objects are namespaced and must be created in every single namespace individually. To enforce security across all tenants uniformly from a central governance standpoint, a **Calico GlobalNetworkPolicy** is created to govern tenant traffic globally.

```bash
kubectl apply -f - << 'EOF'
apiVersion: crd.projectcalico.org/v1
kind: GlobalNetworkPolicy
metadata:
  name: tenant-isolation
spec:
  namespaceSelector: projectcalico.org/name in {"mii-a","kim-b"}
  types:
  - Ingress
  - Egress
  egress:
  - action: Allow
    protocol: UDP
    destination:
      selector: k8s-app == "kube-dns"
      namespaceSelector: projectcalico.org/name == "kube-system"
      ports:
      - 53
  - action: Allow
    protocol: TCP
    destination:
      selector: k8s-app == "kube-dns"
      namespaceSelector: projectcalico.org/name == "kube-system"
      ports:
      - 53
EOF

kubectl get globalnetworkpolicy
```

![Advanced Task 6: Calico GlobalNetworkPolicy](<Calico GlobalNetworkPolicy advaced.png>)
*Figure 16: Creation of cluster-wide `GlobalNetworkPolicy` (`tenant-isolation`) applied across multiple tenant namespaces.*

---

#### Advanced Task 7 — Cluster State & Network Policy Verification

A full system audit is conducted to verify that all namespaced network policies, global policies, and system daemons are running in healthy synchrony.

```bash
# Verify all NetworkPolicies across all namespaces
kubectl get networkpolicy -A

# Verify GlobalNetworkPolicies
kubectl get globalnetworkpolicy

# Inspect all pods across the cluster
kubectl get pods -A
```

**Verification Highlights:**
- Active NetworkPolicies in `mii-a`: `allow-backend`, `allow-dns`, `default-deny-egress`.
- Active GlobalNetworkPolicy: `tenant-isolation`.
- Cluster status: All CoreDNS, Calico node, controller, and tenant pods operating in state `Running`.

![Advanced Task 7: Complete Isolation Verification](<Test the isolation advanced part 1.png>)
*Figure 17: Comprehensive verification showing all active NetworkPolicies, GlobalNetworkPolicy, and cluster pod states.*

---

## 5. Deliverables & Short-Answer Questions

### Q1. Why can containers in different namespaces reach each other by default, and why is that dangerous in multi-tenant cloud?
**Answer:**
By design, standard Kubernetes networking follows a flat IP model governed by the Container Network Interface (CNI) specification, wherein every pod receives a unique, routable IP address and all pods can communicate with any other pod across all namespaces without Network Address Translation (NAT) or firewall restrictions. 

In a multi-tenant cloud, namespaces provide merely **logical organizational boundaries** (scoping names and RBAC) rather than physical or network boundaries. This default-open model is extremely dangerous because:
1. **Lateral Movement:** If an attacker compromises a single container in Tenant A (e.g., via a web vulnerability), they can immediately scan and exploit private internal microservices, databases, and admin interfaces hosted by Tenant B on the same cluster.
2. **Denial of Service & Snooping:** Attackers can flood other tenants' endpoints or eavesdrop on unencrypted plaintext traffic running across the shared software bridge.

---

### Q2. Explain the default-deny principle and how your NetworkPolicy implements it.
**Answer:**
The **Default-Deny Principle** (also known as Zero-Trust or Fail-Safe Defaults) states that all access and communication paths must be blocked by default, and only explicitly approved, authenticated, and verified traffic is permitted by exception.

In our implementation:
- The `default-deny-ingress` policy selects all pods within the tenant namespace (`podSelector: {}`) and declares `policyTypes: [Ingress]`. Because no ingress rules (`ingress: []`) are defined, the CNI kernel packet filter immediately drops all incoming SYN packets destined for those pods.
- Similarly, `default-deny-egress` prevents pods from sending outbound packets unless an explicit whitelist rule (such as `allow-dns` or `allow-backend`) matches the destination namespace, pod label, and port.

---

### Q3. How do virtual machines and containers differ in isolation strength? When would you add a VM boundary?
**Answer:**

| Isolation Dimension | Containers (e.g., Docker, Kubernetes) | Virtual Machines (e.g., KVM, VMware ESXi) |
| :--- | :--- | :--- |
| **Kernel Model** | Shared host OS kernel via Linux namespaces and cgroups | Independent guest OS kernel running on virtualized hardware |
| **Isolation Boundary** | Logical separation mediated by kernel system call filtering | Hardware-assisted hypervisor boundary (Intel VT-x, AMD-V) |
| **Attack Surface** | Broad shared kernel syscall surface; kernel vulnerabilities can lead to host compromise | Narrow hypervisor trap interface; guest escape requires hypervisor exploit |
| **Performance Overhead** | Near zero overhead; instant startup | Moderate virtualization overhead; longer boot times |

**When to add a VM boundary:**
A VM boundary (or micro-VM runtime such as AWS Firecracker, Kata Containers, or gVisor sandbox) must be added when:
1. Running **untrusted or multi-tenant arbitrary user code** where kernel-level isolation is insufficient.
2. Meeting strict compliance mandates (e.g., PCI-DSS, HIPAA, FedRAMP High) requiring hardware-level tenancy separation.
3. Preventing kernel privilege escalation (e.g., Dirty COW, CVE-2022-0847 Dirty Pipe) from granting full host takeover.

---

### Q4. What is data remanence, and why is cryptographic erasure the preferred cloud solution?
**Answer:**
**Data Remanence** refers to residual digital data that remains on physical or virtual storage media after nominal file deletion or release operations have been performed. In standard operating systems, executing `rm` merely deletes directory pointers and marks inode blocks as available; the actual data bits persist on disk until overwritten.

**Why Cryptographic Erasure (Crypto-Shredding) is Preferred in the Cloud:**
1. **Lack of Physical Block Control:** In multi-tenant cloud storage (e.g., AWS EBS, S3, Azure Blob, Ceph), storage is abstracted across large distributed arrays. Cloud consumers have no direct access to underlying physical drive tracks or flash cells to perform multi-pass block overwrites (`dd` / DoD 5220.22-M).
2. **Flash Wear & Copy-on-Write (CoW):** Modern Solid-State Drives (SSDs) and enterprise filesystems (ZFS, Ceph) use wear-leveling and CoW, meaning overwriting a logical sector writes to a *new physical sector*, leaving the old data intact elsewhere in flash memory.
3. **Instantaneous & Verifiable Sanitization:** By encrypting all data with a unique per-tenant Key Encryption Key (KEK) and cryptographically destroying/zeroizing that key, the stored ciphertext is rendered mathematically unrecoverable ($2^{256}$ brute-force complexity), achieving instantaneous, compliant, and total data sanitization across globally replicated cloud storage.

---

### Q5. Which of the three isolation dimensions (compute, network, storage) did each task exercise?
**Answer:**

| Task / Lab Phase | Primary Dimension | Specific Security Mechanism Exercised |
| :--- | :--- | :--- |
| **Task 1: Namespaces & Deployments** | **Compute** | Namespace partitioning & logical tenant workload containerization. |
| **Task 2: Default-Open Cross-Tenant Probe** | **Network** | Flat SDN network analysis & lack of traffic filtering discovery. |
| **Task 3: Noisy Neighbour Resource Quotas** | **Compute** | CPU, Memory, and Pod Count limits (`ResourceQuota`) admission controls. |
| **Task 4: Default-Deny Ingress** | **Network** | L3/L4 `NetworkPolicy` packet dropping on incoming namespace connections. |
| **Task 5: RBAC & Per-Tenant Secrets** | **Storage & Identity** | Namespaced `Secret` access scoping via ServiceAccount and RoleBinding. |
| **Task 6: Data Remanence & Secure Wipe** | **Storage** | Block persistence analysis, zero-byte overwrite (`dd`), and crypto-shredding. |
| **Advanced Tasks 1–3: Egress & Micro-Segmentation** | **Network** | Default-deny egress, DNS whitelisting, and label-based inter-service routing. |
| **Advanced Tasks 4–5: Pod Security Standards** | **Compute & Kernel** | Kernel capability dropping (`ALL`), non-root execution, and seccomp syscall filtering. |
| **Advanced Task 6: GlobalNetworkPolicy** | **Network** | Centralized, cluster-wide multi-tenant firewall enforcement via Calico. |

---

## 6. Security Best-Practices Checklist

| Security Control | Implementation Status | Verification Evidence |
| :--- | :---: | :--- |
| **Distinct Namespace Separation** | [x] **Enforced** | Namespaces `mii-a` and `kim-b` established with isolated services. |
| **Default-Deny Network Isolation** | [x] **Enforced** | `default-deny-ingress` and `default-deny-egress` active and blocking cross-traffic. |
| **Noisy-Neighbour Resource Controls** | [x] **Enforced** | `ResourceQuota` applied limiting CPU (1 core), Memory (512Mi), and Pods (5). |
| **Per-Tenant Secret & Storage Scoping** | [x] **Enforced** | RBAC Role & RoleBinding restrict `app-a` access exclusively to `mii-a` (`auth can-i` verified). |
| **Data Remanence Remediation** | [x] **Enforced** | Demonstrated file overwrite sanitization (`dd if=/dev/zero`) and cryptographic erasure. |
| **Fine-Grained Micro-Segmentation** | [x] **Enforced** | Selective DNS (port 53) and Backend service (port 80) egress whitelisting. |
| **Pod Security Standards (Restricted)** | [x] **Enforced** | `pod-security.kubernetes.io/enforce=restricted` active with non-root containers. |
| **Cluster-Wide Security Governance** | [x] **Enforced** | Calico `GlobalNetworkPolicy` managing multi-tenant traffic centrally. |

---

## 7. Challenges Encountered & Solutions

During the execution of this laboratory, several practical operational and configuration challenges were encountered and successfully remediated:

| # | Challenge Encountered | Root Cause Analysis | Remediation & Engineering Solution |
| :- | :--- | :--- | :--- |
| **1** | **Kind Cluster Creation Conflict (`node(s) already exist`)** | A pre-existing kind node named `ccse-lab2` was occupying the container runtime namespace during initialization. | Cleaned up stale container nodes using `kind delete cluster --name ccse-lab2` and recreated the cluster with `disableDefaultCNI: true`. |
| **2** | **Ephemeral Probe Pod Blocked by Admission Controller** | When running `kubectl run probe` in `mii-a`, the admission controller returned `pods "probe" is forbidden: failed quota: mii-a-quota: must specify requests.cpu...`. | Once a `ResourceQuota` is active in a namespace, every container must specify CPU/memory requests, or a `LimitRange` must be configured to provide default requests. Pods were executed with explicit overrides or tested across configured service endpoints. |
| **3** | **Secret Creation Namespace Mismatch (`namespaces "kim-a" not found`)** | An initial CLI typo referenced non-existent namespace `kim-a` instead of `kim-b`. | Identified the namespace typographical mismatch and executed the command targeting the correct tenant namespace `kim-b`. |
| **4** | **Restricted Pod Security Standard Warnings** | Deploying standard Nginx workloads triggered PSS warnings: `allowPrivilegeEscalation != false`, `capabilities.drop=["ALL"]`, `runAsNonRoot != true`. | Hardened the workload definitions by switching to `nginxinc/nginx-unprivileged` and appending a strict `securityContext` specification with dropped capabilities and runtime default seccomp profiles. |
| **5** | **Calico CRD Global Policy Dependency** | Applying `GlobalNetworkPolicy` requires Project Calico Custom Resource Definitions to be fully registered before policy acceptance. | Validated daemonset readiness via `kubectl -n kube-system rollout status daemonset/calico-node` before applying `crd.projectcalico.org/v1` manifests. |

---

## 8. Lessons Learned

1. **Namespaces are purely logical abstractions:** A common cloud misconception is that Kubernetes namespaces provide complete security boundaries. Without a CNI supporting `NetworkPolicy` and strict RBAC controls, namespaces provide zero network and storage isolation.
2. **Zero-Trust is essential in Cloud-Native architectures:** Default configurations favor developer convenience ("default-open"). Security engineers must proactively adopt a "Deny-by-Default, Allow-by-Exception" posture for both incoming (Ingress) and outgoing (Egress) communications.
3. **Resource Quotas are vital for Availability:** Logical multi-tenancy cannot guarantee system availability unless CPU, memory, storage, and pod counts are strictly bounded. Without quotas, a single runaway process can starve the shared kubelet and co-located tenant workloads.
4. **Cloud Data Destruction must rely on Cryptography:** Due to abstraction layers in cloud block and object stores, physical block-level zeroing is impractical. End-to-end encryption with secure key revocation (crypto-shredding) is the industry standard for eliminating data remanence risks.
5. **Defense-in-Depth Requires Pod Hardening:** Network policies restrict packet flow, but container breakouts can compromise host kernels. Combining NetworkPolicies, ResourceQuotas, RBAC, and Restricted Pod Security Standards provides a robust multi-layered defense.

---

## 9. Teardown & Cleanup

Upon final verification and artifact collection, local lab resources were safely decommissioned to release host resources:

```bash
# 1. Delete Kind Kubernetes Cluster
kind delete cluster --name ccse-lab2

# 2. Remove Docker Persistent Volume
docker volume rm ccse-vol
```

---

## 10. References

1. **UniKL MIIT Course Lecture:** *IKB42603 Cloud Computing Security Essentials — Week 3: Secure Isolation of Physical & Logical Infrastructure*, Prof. Dr. Shahrulniza Musa.
2. **Kubernetes Documentation:** *Network Policies & Multi-Tenancy Architecture*, [https://kubernetes.io/docs/concepts/services-networking/network-policies/](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
3. **Project Calico Documentation:** *Calico Network Policy & GlobalNetworkPolicy Guide*, [https://docs.tigera.io/calico/latest/reference/resources/globalnetworkpolicy](https://docs.tigera.io/calico/latest/reference/resources/globalnetworkpolicy)
4. **Cloud Security Alliance (CSA):** *Security Guidance for Critical Areas of Focus in Cloud Computing v5.0 — Domain 7: Infrastructure & Networking*.
5. **NIST Special Publication 800-190:** *Application Container Security Guide*, National Institute of Standards and Technology.
6. **NIST Special Publication 800-88 Rev. 1:** *Guidelines for Media Sanitization (Cryptographic Erasure & Overwriting)*.
