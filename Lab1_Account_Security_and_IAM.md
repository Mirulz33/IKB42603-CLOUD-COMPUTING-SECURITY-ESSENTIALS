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
| All-powerful owner | Root user | Has full access to all AWS services and settings. |
| Human/app identity | IAM User | Represents a person or application that can log in and use AWS. |
| Permission bundle | IAM Policy | Defines what actions are allowed or denied. |
| Collection of users | IAM Group | A collection of IAM users that allows you to easily manage and apply the same policies/permissions to multiple users at once. |
| Temporary identity | IAM Role | Provides temporary permissions to users or services when needed. |

### Task 2 — Create a Least-Privilege Admin (Stop Using Root)
The root user is a liability, so a dedicated admin identity was created and granted permissions through a group instead of directly to the user.

![Task 2 — Create a Least-Privilege Admin (Stop Using Root) part 1](Task%202%20—%20Create%20a%20Least-Privilege%20Admin%20(Stop%20Using%20Root)%20part%201.png)

<img width="561" height="562" alt="Task 2 — Create a Least-Privilege Admin (Stop Using Root) part 1" src="https://github.com/user-attachments/assets/a85cd7f6-2d5d-49f0-b452-424e5d1472e8" />




![Task 2 — Create a Least-Privilege Admin (Stop Using Root) part 2](Task%202%20—%20Create%20a%20Least-Privilege%20Admin%20(Stop%20Using%20Root)%20part%202.png)

<img width="607" height="395" alt="Task 2 — Create a Least-Privilege Admin (Stop Using Root) part 2" src="https://github.com/user-attachments/assets/17840d20-6f16-4283-b3ef-9848adc3b9b6" />




### Task 3 — Enforce Least Privilege with a Scoped Policy
A read-only user account was created to demonstrate fine-grained authorization.

![Task 3 — Enforce Least Privilege with a Scoped Policy](Task%203%20—%20Enforce%20Least%20Privilege%20with%20a%20Scoped%20Policy.png)

<img width="607" height="395" alt="Task 3 — Enforce Least Privilege with a Scoped Policy" src="https://github.com/user-attachments/assets/eea57500-2f1d-48b5-8eb7-9fbbc8c9ac07" />



### Task 4 — Credential Hygiene & Access Keys
Programmatic access uses access keys. In this task, long-lived access keys were created, listed, and rotated (deactivated) to practice credential hygiene.

![Task 4 — Credential Hygiene & Access Keys](Task%204%20—%20Credential%20Hygiene%20&%20Access%20Keys.png)

<img width="626" height="716" alt="Task 4 — Credential Hygiene   Access Keys" src="https://github.com/user-attachments/assets/12cfb240-af1c-4d14-8570-1494d13116f3" />


### Task 6 — Define a Role and Bind It (Least Privilege)
A Role was created to only allow reading pods in the `dev` namespace, and it was bound to a developer test service account.

![Task 6 — Define a Role and Bind It (Least Privilege)](Task%206%20—%20Define%20a%20Role%20and%20Bind%20It%20(Least%20Privilege).png)

<img width="555" height="280" alt="Task 6 — Define a Role and Bind It (Least Privilege)" src="https://github.com/user-attachments/assets/933db7cc-6478-4671-90b6-05f68bfe2f8c" />



### Task 7 — Test That Access Control Works
We verified the boundaries using `kubectl auth can-i`. The service account successfully authenticated, but authorization blocked the delete action and access to the `prod` namespace.

![Task 7 — Test That Access Control Works](Task%207%20—%20Test%20That%20Access%20Control%20Works.png)

<img width="491" height="245" alt="Task 7 — Test That Access Control Works" src="https://github.com/user-attachments/assets/fa22c680-5fa9-4d54-8b0f-5fa5f83fa0ba" />



### Verification Command
Proof of cluster RBAC role binding for the cluster.

![3. Verification Command](3.%20Verification%20Command.png)}

<img width="547" height="312" alt="3  Verification Command" src="https://github.com/user-attachments/assets/11519521-a3ba-482b-a526-7721f9f3561d" />


---

## Short-Answer Questions

**Q1. Why is attaching policies to groups better than attaching them directly to users?**

Attaching policies to groups is easier to manage. You only need to assign permissions to the group, and all users in that group automatically get the same permissions. This saves time and keeps permissions consistent.

**Q2. What is the difference between an IAM User and an IAM Role?**


IAM User: A permanent identity for a person or application with its own username and password or access keys.

IAM Role: A temporary identity that is assumed when needed. It does not have permanent login credentials.


**Q3. Explain least privilege using the Analyst account, and how it reduces blast radius if compromised.**


The Analyst account only has the permissions needed to do its job, such as viewing data. It cannot delete or change important resources. If the account is hacked, the attacker can only perform limited actions, reducing the damage (blast radius).


**Q4. In Kubernetes, what is the difference between a Role and a RoleBinding?**


Role: Defines what actions are allowed, such as reading pods.

RoleBinding: Connects the Role to a user, group, or service account so they receive those permissions.



**Q5. Why did the developer service account fail to access prod, and which security principle does that demonstrate?**

The developer service account failed because it did not have permission to access the production (prod) environment. This demonstrates the Principle of Least Privilege, where accounts only receive the permissions they need for their work.


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
