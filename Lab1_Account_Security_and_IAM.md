# Lab 1 - Account Security, Identity & Access Management Report

## Objective
To understand and apply the principles of cloud account security, identity governance, and least privilege using LocalStack (an AWS simulator) and Kubernetes RBAC.

## Learning Outcomes
1. Stand up a local cloud lab using Docker and LocalStack.
2. Apply the principle of least privilege by replacing root usage with scoped IAM users, groups, and policies.
3. Create and test fine-grained permissions, distinguishing what an identity is *allowed* versus *denied* to do.
4. Implement and verify Role-Based Access Control (RBAC) in Kubernetes, the real enforcement engine.
5. Audit identities and reason about MFA, access keys, and credential hygiene.

## Environment
- Docker Desktop / Docker Engine
- LocalStack (AWS-compatible cloud simulator)
- AWS CLI v2
- kind (Kubernetes-in-Docker) and kubectl

---

## Step-by-Step Report

### Task 1 — Map the Cloud Identity Landscape

| Concept | AWS term | Purpose |
| :--- | :--- | :--- |
| All-powerful owner | Root user | The absolute owner of the account with complete, unrestricted access to all resources and billing. It should not be used for daily tasks. |
| Human/app identity | IAM User | Represents a specific person or application that needs to interact with AWS services, using long-term credentials. |
| Permission bundle | IAM Policy | A document (usually in JSON) that explicitly defines permissions, detailing what actions are allowed or denied on which resources. |
| Collection of users | IAM Group | A logical collection of IAM users that allows you to easily manage and apply the same policies/permissions to multiple users at once. |
| Temporary identity | IAM Role | An identity with temporary credentials that can be assumed by anyone who needs it (users, apps, or AWS services) for a specific duration. |

### Task 2 — Create a Least-Privilege Admin (Stop Using Root)
The root user is a liability, so a dedicated admin identity was created and granted permissions through a group instead of directly to the user.

![Task 2 — Create a Least-Privilege Admin (Stop Using Root) part 1](Task%202%20—%20Create%20a%20Least-Privilege%20Admin%20(Stop%20Using%20Root)%20part%201.png)

![Task 2 — Create a Least-Privilege Admin (Stop Using Root) part 2](Task%202%20—%20Create%20a%20Least-Privilege%20Admin%20(Stop%20Using%20Root)%20part%202.png)

### Task 3 — Enforce Least Privilege with a Scoped Policy
A read-only user account was created to demonstrate fine-grained authorization.

![Task 3 — Enforce Least Privilege with a Scoped Policy](Task%203%20—%20Enforce%20Least%20Privilege%20with%20a%20Scoped%20Policy.png)

### Task 4 — Credential Hygiene & Access Keys
Programmatic access uses access keys. In this task, long-lived access keys were created, listed, and rotated (deactivated) to practice credential hygiene.

![Task 4 — Credential Hygiene & Access Keys](Task%204%20—%20Credential%20Hygiene%20&%20Access%20Keys.png)

### Task 6 — Define a Role and Bind It (Least Privilege)
A Role was created to only allow reading pods in the `dev` namespace, and it was bound to a developer test service account.

![Task 6 — Define a Role and Bind It (Least Privilege)](Task%206%20—%20Define%20a%20Role%20and%20Bind%20It%20(Least%20Privilege).png)

### Task 7 — Test That Access Control Works
We verified the boundaries using `kubectl auth can-i`. The service account successfully authenticated, but authorization blocked the delete action and access to the `prod` namespace.

![Task 7 — Test That Access Control Works](Task%207%20—%20Test%20That%20Access%20Control%20Works.png)

### Verification Command
Proof of cluster RBAC role binding for the cluster.

![3. Verification Command](3.%20Verification%20Command.png)

---

## Short-Answer Questions

**Q1. Why is attaching policies to groups better than attaching them directly to users?**
It makes managing permissions much easier and scalable. Instead of updating policies for every single user, you simply attach the policy to a group once. When a user joins or leaves a team, you only need to add or remove them from the group, and their permissions update automatically. This ensures permissions remain manageable and auditable at scale.

**Q2. What is the difference between an IAM User and an IAM Role?**
An **IAM User** represents a specific individual or application and typically has long-term credentials (password or access keys). An **IAM Role** is a temporary identity that doesn't have long-term credentials; instead, it provides temporary access and can be "assumed" by users, applications, or services when needed.

**Q3. Explain least privilege using the Analyst account, and how it reduces blast radius if compromised.**
Least privilege means granting only the exact permissions needed for a job and nothing more. The Analyst account only requires reading data, so it was strictly given a read-only policy. This reduces the blast radius because if an attacker steals the Analyst credentials, the damage is limited to just viewing data—they cannot delete resources, create expensive infrastructure, or change configurations. 

**Q4. In Kubernetes, what is the difference between a Role and a RoleBinding?**
A **Role** defines the rules (the permissions), specifying *what* actions are allowed on *which* resources (e.g., allow `get` and `list` on `pods`). A **RoleBinding** assigns that Role to specific users or service accounts, answering *who* gets those permissions.

**Q5. Why did the developer service account fail to access prod, and which security principle does that demonstrate?**
The service account failed to access `prod` because its RoleBinding only granted permissions within the `dev` namespace. This perfectly demonstrates the **Principle of Least Privilege**, as the platform enforced that the developer could only access what they explicitly needed, keeping `prod` strictly off-limits.

---

## Challenges Encountered
During the lab, one of the main challenges was understanding the conceptual difference between authentication (proving who you are) and authorization (what you are allowed to do), especially when verifying access controls in Kubernetes using `kubectl auth can-i`. Another minor challenge was ensuring that the AWS CLI was consistently pointed to the LocalStack endpoint rather than attempting to connect to actual AWS services, which required setting up and remembering the endpoint alias properly.

## Lessons Learned
- Using root accounts for daily operations is a severe security risk and should be avoided at all costs.
- Managing permissions via groups significantly reduces administrative overhead and makes auditing easier.
- Fine-grained access control (RBAC) in platforms like Kubernetes is essential to securely isolate environments (e.g., dev vs. prod).
- Proper credential hygiene, such as rotating and disabling old access keys, protects against unauthorized long-term access.

## References
- IKB42603 Lab Manual (Weeks 1-2): Cloud Account Security, Identity & Access Management
- Course lectures — Week 1 (Fundamentals), Week 2 (Security Architecture), Week 5 (Access Control), Week 7 (Identity Management)
- LocalStack documentation — [docs.localstack.cloud](https://docs.localstack.cloud/)
- Kubernetes RBAC — [kubernetes.io/docs/reference/access-authn-authz/rbac](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
- CSA Security Guidance v5 — Domain on Identity & Access Management
