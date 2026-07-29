# Lab 0: Environment Setup
Course Information

Course: IKB42603 Cloud Computing Security Essentials

Lab: Lab 0 - Environment Setup

Name: Muhamed Hamirul Bin Mohd Bazri

Date: 30 July 2026


## Objective
To successfully set up the local development environment required for IKB42603 Cloud Computing Security Essentials labs, ensuring all necessary tools (Docker, AWS CLI, kind, kubectl, and helper tools) are installed and configured correctly.

## Learning Outcomes
By the end of this lab, students should be able to:
- Install and configure Docker for running containers and LocalStack.
- Install and configure AWS CLI v2 for interacting with LocalStack.
- Set up a local Kubernetes cluster using `kind` and manage it using `kubectl`.
- Verify the installation of helper tools such as OpenSSL, oathtool, and Trivy.

## Environment
- **Operating System:** Windows / macOS / Linux
- **Tools Required:** Docker, AWS CLI v2, kind, kubectl, OpenSSL, oathtool, Trivy

## 1. Install and verify Docker

Install Docker for your operating system:

- **Windows 10/11:** Install Docker Desktop, select the **WSL 2** backend, then reboot.
- **macOS:** Install the Docker Desktop build for Apple Silicon or Intel, as appropriate.
- **Ubuntu Linux:**

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
```

After the Linux group change, log out and back in. Verify Docker:

```bash
docker --version
docker run --rm hello-world
```

Expected result: a Docker version is printed and the second command displays `Hello from Docker!`.

**Evidence — Docker version**
<img width="630" height="72" alt="docker install vesion" src="https://github.com/user-attachments/assets/5388f7de-ea41-4d4c-b212-8668eca54421" />


![Docker version output](<docker install vesion.png>)

**Evidence — Docker container test**

<img width="642" height="507" alt="docker run hello world" src="https://github.com/user-attachments/assets/3221078e-ca70-40e7-9e75-ae506f22fc90" />


![Docker hello-world output](<docker run hello world.png>)

## 2. Install and verify AWS CLI v2

Install AWS CLI v2 for your operating system:

- **Windows:** Download and run the AWS CLI v2 MSI installer from AWS.
- **macOS:** `brew install awscli` or use the AWS `.pkg` installer.
- **Linux:**

```bash
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o awscliv2.zip
unzip awscliv2.zip && sudo ./aws/install
```

Verify the installation:

```bash
aws --version
```

Expected result: an `aws-cli/2.x` version is printed.

**Evidence — AWS CLI v2 installed**


<img width="607" height="80" alt="image" src="https://github.com/user-attachments/assets/340b89c6-6f03-4c52-b3fa-dc5f5ce77aa1" />

![AWS CLI version output](<AWS install version.png>)

## 3. Install and verify kind and kubectl

Install both tools for your operating system:

```bash
# Windows (Chocolatey)
choco install kind
choco install kubernetes-cli

# macOS (Homebrew)
brew install kind
brew install kubectl

# Linux: kind
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.23.0/kind-linux-amd64
chmod +x ./kind && sudo mv ./kind /usr/local/bin/kind

# Linux: kubectl
sudo snap install kubectl --classic
```

Run the verification commands:

```bash
kind --version
kubectl version --client
```

Expected result: both commands print client version information.

**Evidence — kind and kubectl installed**

<img width="395" height="192" alt="image" src="https://github.com/user-attachments/assets/89f20ae8-f9a3-458a-8646-dffd21f27fd8" />

![kind and kubectl version output](<kind & kuberctl version.png>)

## 4. Install or verify helper tools

- **OpenSSL:** Already available on macOS/Linux; Windows users can use the copy included with Git Bash.
- **oathtool:**

```bash
# macOS
brew install oath-toolkit

# Linux
sudo apt install oathtool
```

  On Windows, use WSL or a phone authenticator app.

- **Trivy:** No separate installation is required by the guide. Lab 4 can run it with Docker:

```bash
docker run --rm aquasec/trivy image <image-name>
```

Verify applicable local tools:

```bash
openssl version
oathtool --version
trivy --version
```

Expected result: OpenSSL and oathtool print their versions. The supplied environment also has a local Trivy installation.

**Evidence — helper tools available**


<img width="640" height="356" alt="image" src="https://github.com/user-attachments/assets/32b6b781-aee4-4e81-b04c-89a3635b4c50" />

![OpenSSL, oathtool, and Trivy version output](<Helper Tools (OpenSSL, oathtool, Trivy) version.png>)

## 5. Prepare, start, and verify LocalStack

The first LocalStack start downloads its image. You may pre-pull it first:

```bash
docker pull localstack/localstack:3.8
```

**Evidence — LocalStack image `3.8` pulled**

<img width="670" height="522" alt="image" src="https://github.com/user-attachments/assets/2057557d-886b-4e8c-af0e-01bdea5ccabd" />

![LocalStack 3.8 image pull output](<docker pull lab enviroment.png>)

**Additional evidence — LocalStack latest image pulled**

<img width="632" height="197" alt="image" src="https://github.com/user-attachments/assets/28f61643-4c50-44a4-a488-c39b184ae729" />

![LocalStack latest image pull output](<Screenshot 2026-07-28 195421.png>)

Start LocalStack using the guide command, then check its health endpoint:

```bash
docker run -d --name localstack -p 4566:4566 localstack/localstack
curl http://localhost:4566/_localstack/health
```

Expected result: the health request returns JSON showing LocalStack services are available.

**Evidence — LocalStack health response**
<img width="647" height="252" alt="image" src="https://github.com/user-attachments/assets/491f3c16-69bb-45bf-b7c5-9930fca734a5" />

![LocalStack health-check output](<Screenshot 2026-07-29 194112.png>)

Manage the LocalStack container when needed:

```bash
docker stop localstack
docker start localstack
docker rm -f localstack
```

## 6. Configure AWS CLI for LocalStack

Set dummy credentials once, then use the LocalStack endpoint:

```bash
aws configure set aws_access_key_id test
aws configure set aws_secret_access_key test
aws configure set region us-east-1

EP='--endpoint-url=http://localhost:4566'
aws $EP sts get-caller-identity
```

Expected result: `sts get-caller-identity` returns an identity, proving that AWS CLI is communicating with LocalStack.

**Evidence — AWS CLI configuration and LocalStack identity test**

<img width="487" height="371" alt="image" src="https://github.com/user-attachments/assets/9de84012-7602-4d13-bee7-c65e5a505bd0" />

![AWS CLI configured for LocalStack and identity returned](<AWS CLI Configuration.png>)

## 7. Create and verify the kind Kubernetes cluster

Create the cluster named `ccse`, then confirm its context and node status:

```bash
kind create cluster --name ccse
kubectl cluster-info --context kind-ccse
kubectl get nodes
```

Expected result: the `ccse-control-plane` node is listed with status `Ready`.

**Evidence — kind cluster created and node ready**

<img width="641" height="532" alt="image" src="https://github.com/user-attachments/assets/8f2fe9d7-8b63-4090-b402-1451d1e2a937" />

![kind cluster creation, cluster info, and node status](<Kubernetes cluster (kind) version.png>)

Remove the cluster after the lab if required:

```bash
kind delete cluster --name ccse
```

## 8. Final pre-lab checklist

- [x] `docker --version` prints a version.
- [x] `docker run --rm hello-world` succeeds.
- [x] `aws --version` prints an AWS CLI v2 version.
- [x] `kind --version` and `kubectl version --client` succeed.
- [x] LocalStack health responds at port `4566`.
- [x] `aws $EP sts get-caller-identity` returns an identity.
- [x] `kubectl get nodes` shows a `Ready` node.

## Quick fixes

- **Docker will not start:** Enable hardware virtualization (VT-x, AMD-V, or SVM) in BIOS/UEFI. On Windows, also enable WSL 2 and Virtual Machine Platform.
- **Port 4566 is in use:** Run `docker rm -f localstack`, then start LocalStack again.
- **AWS endpoint error:** Start LocalStack and include `$EP` / `--endpoint-url=http://localhost:4566` in the command.
- **kind cluster creation fails:** Ensure Docker is running and has at least 4 GB of memory available.

## Optional cleanup

```bash
docker rm -f localstack
kind delete clusters --all
docker system prune -f
```

Removing containers and clusters is safe; screenshots and report files remain on the laptop.

## Challenges Encountered
- **Hardware Virtualization:** Ensuring VT-x/AMD-V and WSL 2 are properly enabled on Windows for Docker to function correctly.
- **Path Issues:** Ensuring all installed CLI tools (like AWS CLI and kind) are correctly added to the system PATH so they can be accessed from the terminal.
- **Terminal Compatibility:** Some commands require a Bash environment (like Git Bash or WSL on Windows) rather than Command Prompt or PowerShell.

## Lessons Learned
- **Environment Consistency:** Using Docker ensures that the environment (like LocalStack and Trivy) remains consistent across different operating systems.
- **Local Cloud Simulation:** LocalStack provides an excellent way to practice AWS commands locally without needing a real AWS account or incurring costs.
- **Kubernetes in Docker:** `kind` is a lightweight and effective way to spin up Kubernetes clusters locally for testing and development.

## Conclusion
The local environment setup was completed successfully. By installing Docker, AWS CLI, `kind`, `kubectl`, and the required helper tools, a robust and isolated local testing environment has been established. This ensures readiness for the upcoming Cloud Computing Security Essentials labs, allowing for safe and efficient experimentation with cloud and container security concepts without relying on external cloud resources.

## References
- IKB42603 Cloud Computing Security Essentials - Setup Cheatsheet (Prof. Dr. Shahrulniza Musa)
- [Docker Documentation](https://docs.docker.com/)
- [AWS CLI Documentation](https://docs.aws.amazon.com/cli/)
- [kind Documentation](https://kind.sigs.k8s.io/)
- [LocalStack Documentation](https://docs.localstack.cloud/)
