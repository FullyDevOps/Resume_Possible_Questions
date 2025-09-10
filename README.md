---

# 📘 FULL RESUME-BASED Q&A — TECHNOLOGY BY TECHNOLOGY

---

## 🔹 1. Microsoft Azure (General)

### ❓ Q: What is Microsoft Azure and how have you used it in your projects?

### ✅ Theoretical:
Microsoft Azure is a public cloud platform offering IaaS, PaaS, and SaaS services including compute, storage, networking, databases, AI, and DevOps tools. It enables scalable, secure, and globally distributed application hosting with pay-as-you-go pricing. Core pillars: Compute (VMs, AKS, Functions), Storage (Blob, Disk, Files), Networking (VNet, LB, App Gateway), Security (Key Vault, AD, RBAC), and Monitoring (Monitor, Log Analytics).

### 💼 Real-Time Experience:
At **Indiana University Health & Lanvera**, I architected end-to-end Azure solutions:  
→ Provisioned **Azure VMs** with ARM/Terraform for legacy app hosting.  
→ Deployed **AKS clusters** with node pools, network policies, HPA.  
→ Secured apps using **Application Gateway + WAF**, **Private Endpoints** to SQL/Storage.  
→ Automated backups using **Azure Backup Vault**, DR with **Site Recovery**.  
→ Enforced governance via **Azure Policy**, **RBAC**, **Managed Identities**.  
→ Reduced infra provisioning time from 2 days → 20 mins via IaC.

---

## 🔹 2. Google Cloud Platform (GCP)

### ❓ Q: Describe your experience with GCP. How does it compare to Azure?

### ✅ Theoretical:
GCP offers global infrastructure with services like Compute Engine (VMs), GKE (managed Kubernetes), Cloud Functions (serverless), Cloud Storage (object), BigQuery (analytics), and Anthos (hybrid). Key strengths: global VPC, live migration, per-second billing, deep Kubernetes integration. Compared to Azure: GCP has stronger open-source/K8s focus; Azure has deeper enterprise/Windows integration.

### 💼 Real-Time Experience:
At **IU Health**, I:  
→ Built **GKE clusters** with Workload Identity, node auto-provisioning, cluster autoscaler.  
→ Used **Cloud Storage** with uniform bucket-level access + retention policies.  
→ Deployed **Cloud Functions** (Python) triggered by Pub/Sub for log processing.  
→ Configured **VPCs** with private services access + **Cloud NAT** for egress.  
→ Integrated **Istio via Anthos** for cross-cluster service mesh.  
→ Used **Cloud Build** for CI → Artifact Registry → GKE deployments.  
→ Enforced security via **IAM custom roles** and **VPC Service Controls**.

---

## 🔹 3. Infrastructure as Code (IaC) — Terraform

### ❓ Q: What is Terraform? How have you used it to manage cloud infrastructure?

### ✅ Theoretical:
Terraform is an open-source IaC tool using HCL to define, provision, and manage cloud resources declaratively. Providers (AzureRM, Google) abstract APIs. State file tracks real-world resources. Benefits: multi-cloud, version control, collaboration, drift detection. Terraform Cloud adds remote state, locking, policy as code (Sentinel), run triggers.

### 💼 Real-Time Experience:
At **Lanvera & IU Health**:  
→ Wrote **Terraform modules** for AKS, GKE, VNets, VPCs, Blob/Cloud Storage.  
→ Used **Terraform Cloud** for state locking + policy enforcement (blocked public buckets).  
→ Imported legacy resources using `terraform import` → brought under IaC control.  
→ Integrated into **Jenkins/Azure DevOps** — auto-apply on Git merge to main.  
→ Reduced configuration drift by 95% — all infra changes auditable via Git.

---

## 🔹 4. ARM Templates

### ❓ Q: What are ARM Templates? When would you choose them over Terraform?

### ✅ Theoretical:
ARM (Azure Resource Manager) Templates are Azure-native JSON templates for declarative resource provisioning. Tightly integrated with Azure Portal, CLI, Policy. Best for Azure-only environments, GovCloud compliance, or when leveraging Azure-native features not yet in Terraform provider. Less portable than Terraform.

### 💼 Real-Time Experience:
At **IU Health**, I:  
→ Used **ARM Templates** for Azure GovCloud projects requiring strict compliance.  
→ Deployed **App Gateway + WAF**, **Private Endpoints**, **Backup Vaults** via ARM.  
→ Integrated templates into **Azure DevOps Pipelines** — parameterized per env (dev/stage/prod).  
→ Combined with Terraform — used ARM for Azure-specific resources, Terraform for multi-cloud.

---

## 🔹 5. Azure CLI / gcloud CLI

### ❓ Q: How do you use Azure CLI and gcloud CLI in automation?

### ✅ Theoretical:
Azure CLI (az) and gcloud CLI are command-line tools to manage cloud resources. Used in scripts for automation, CI/CD, ad-hoc tasks. More flexible than GUI, scriptable, integrates with Bash/PowerShell/Python. Can authenticate via Service Principal/Managed Identity.

### 💼 Real-Time Experience:
At **IU Health & Lanvera**:  
→ Wrote **Bash/PowerShell scripts** using `az` and `gcloud` to:  
  - Auto-tag resources on creation.  
  - Rotate secrets in Key Vault/Secret Manager.  
  - Scale AKS node pools during peak hours.  
→ Integrated into **Jenkins pipelines** — e.g., `az acr build` triggered on Git push.  
→ Used `gcloud compute instances list --filter="status=RUNNING"` for inventory audits.

---

## 🔹 6. Kubernetes (AKS, GKE, OpenShift)

### ❓ Q: Explain your experience with Kubernetes on Azure and GCP.

### ✅ Theoretical:
Kubernetes automates container orchestration — deployment, scaling, self-healing. AKS (Azure) and GKE (GCP) are managed services — control plane managed by cloud provider. Features: Deployments, Services, ConfigMaps, Secrets, HPA, Ingress. OpenShift adds developer portal, built-in CI/CD, security.

### 💼 Real-Time Experience:
At **IU Health, Lanvera, Ksolves**:  
→ Managed **multi-node AKS/GKE clusters** — configured **HPA**, **Pod Disruption Budgets**, **affinity rules**.  
→ Deployed apps via **Helm charts** — environment-specific values (dev/stage/prod).  
→ Secured with **Network Policies**, **Pod Security Policies**.  
→ At **Ksolves**, administered **OpenShift** for hybrid cloud — beyond vanilla K8s.  
→ Used **kubectl**, **Helm**, **Lens IDE** for day-to-day management.  
→ Reduced deployment failures by 80% via health probes + readiness gates.

---

## 🔹 7. Helm

### ❓ Q: What is Helm? How have you used it in your Kubernetes deployments?

### ✅ Theoretical:
Helm is a package manager for Kubernetes — bundles apps into “charts” (YAML templates + values). Enables versioning, rollbacks, dependency management. Charts can be shared via repositories (Artifact Hub, ACR, GCR). Values files allow environment-specific configs.

### 💼 Real-Time Experience:
At **IU Health & Lanvera**:  
→ Created **Helm charts** for Java/Python microservices — templated Deployments, Services, Ingress, ConfigMaps.  
→ Used `values-dev.yaml`, `values-prod.yaml` for env-specific configs (replicas, image tags, resource limits).  
→ Integrated into **Jenkins pipelines** — `helm upgrade --install` on merge to main.  
→ Enabled **auto-rollback** on health check failure — zero-downtime releases.  
→ Stored charts in **Azure Container Registry (ACR)** as OCI artifacts.

---

## 🔹 8. Istio Service Mesh

### ❓ Q: What is Istio? Why did you implement it in your projects?

### ✅ Theoretical:
Istio is a service mesh for microservices — adds traffic management (canary, blue-green), security (mTLS, authz), and observability (metrics, traces) without app code changes. Uses sidecar proxies (Envoy). Components: Pilot (traffic), Citadel (security), Galley (config), Mixer (telemetry — deprecated).

### 💼 Real-Time Experience:
At **Lanvera & IU Health**:  
→ Deployed **Istio on AKS/GKE** — configured **VirtualServices** for canary releases (5% → 100%).  
→ Enforced **mTLS** between all services — zero plain-text traffic.  
→ Used **Kiali + Grafana** dashboards to visualize latency, error rates, traffic flows.  
→ Defined **AuthorizationPolicies** — e.g., “payment-service can only be called by checkout-service”.  
→ Reduced MTTR by 60% — traces showed exact failing service in chain.

---

## 🔹 9. CI/CD — Jenkins

### ❓ Q: How have you designed CI/CD pipelines using Jenkins?

### ✅ Theoretical:
Jenkins is an open-source automation server for CI/CD. Uses plugins for Git, Docker, Kubernetes, etc. Pipelines defined as code (Jenkinsfile) — stages (build, test, deploy), agents, parallel steps, approvals. Integrates with SCM (Git), artifact repos (Nexus, ACR), deployment tools (Helm, kubectl).

### 💼 Real-Time Experience:
At **IU Health & Lanvera**:  
→ Built **Jenkins pipelines** (Declarative + Scripted) triggered on Git commit:  
  1. Checkout → 2. Unit Tests → 3. SonarQube → 4. Trivy Scan → 5. Docker Build → 6. Push to ACR → 7. Helm Deploy to AKS/GKE → 8. Smoke Tests → 9. Manual Prod Approval.  
→ Used **Kubernetes Plugin** — dynamic agents in AKS.  
→ Stored credentials in **Azure Key Vault** — injected via Credentials Binding.  
→ Enabled **auto-rollback** on test failure — `helm rollback`.  
→ Reduced release cycle from 2 weeks → 2 hours.

---

## 🔹 10. Azure DevOps Pipelines

### ❓ Q: How is Azure DevOps different from Jenkins? When did you use it?

### ✅ Theoretical:
Azure DevOps is Microsoft’s SaaS DevOps platform — includes Repos, Pipelines, Boards, Artifacts. Pipelines use YAML — tightly integrated with Azure services (ARM, AKS, ACR). Better for Azure-native teams. Jenkins is more flexible, plugin-rich, open-source.

### 💼 Real-Time Experience:
At **Lanvera**:  
→ Used **Azure DevOps YAML pipelines** for .NET apps on **App Services**.  
→ Implemented **blue-green deployments** using **deployment slots** — swap on approval.  
→ Integrated with **Azure Repos** — PR triggers, branch policies.  
→ Used **Service Connections** with Managed Identity for secure Azure access.  
→ Preferred for Azure-only projects — faster setup than Jenkins.

---

## 🔹 11. GitHub Actions

### ❓ Q: Have you used GitHub Actions? How does it compare to Jenkins?

### ✅ Theoretical:
GitHub Actions is CI/CD integrated into GitHub — workflows defined in `.github/workflows/*.yml`. Triggers on push, PR, schedule. Uses “runners” (hosted or self-hosted). Simpler for GitHub-hosted repos. Less flexible than Jenkins for complex workflows.

### 💼 Real-Time Experience:
At **IU Health** (for smaller projects):  
→ Used **GitHub Actions** for static site deployments to **Azure Static Web Apps**.  
→ Workflow: `push to main` → `build Jekyll site` → `deploy to Azure`.  
→ Used **secrets in GitHub** — injected as env vars.  
→ Faster for simple projects — no Jenkins master to maintain.

---

## 🔹 12. Ansible

### ❓ Q: How have you used Ansible for configuration management?

### ✅ Theoretical:
Ansible is agentless config management — uses SSH/WinRM. Playbooks (YAML) define tasks (install packages, copy files, start services). Idempotent — safe to run repeatedly. Modules for cloud (azure_rm, gcp), Docker, Kubernetes. Integrates with CI/CD.

### 💼 Real-Time Experience:
At **Lanvera & Ksolves**:  
→ Wrote **Ansible playbooks** to:  
  - Configure 100+ Azure VMs — install Java, Tomcat, deploy WAR files.  
  - Enforce security baselines — disable root SSH, set up auditd, install agents.  
→ Integrated into **Jenkins pipelines** — ran after VM creation.  
→ Used **dynamic inventories** — `azure_rm` plugin to target VMs by tag.  
→ Replaced manual config — eliminated “snowflake servers”.

---

## 🔹 13. Docker & ACR

### ❓ Q: Explain your Docker workflow and integration with Azure Container Registry.

### ✅ Theoretical:
Docker packages apps into containers — built from Dockerfile (layers). Images stored in registries (Docker Hub, ACR, GCR). ACR is Azure’s private registry — geo-replicated, webhook triggers, vulnerability scanning. Best practices: multi-stage builds, non-root user, health checks.

### 💼 Real-Time Experience:
At **IU Health & Ksolves**:  
→ Built **Dockerfiles** for Java/Python apps — multi-stage, Alpine base, non-root user.  
→ Scanned images with **Trivy** in CI — blocked on critical CVEs.  
→ Pushed to **ACR** with geo-replication (US East + West).  
→ Used **ACR Tasks** — auto-build on Git push.  
→ Pulled by AKS/GKE — imagePullSecrets auto-injected via Managed Identity.  
→ Reduced image size by 70% — faster deployments.

---

## 🔹 14. Azure Networking — VNet, NSG, Load Balancer, App Gateway

### ❓ Q: How have you designed secure Azure networks?

### ✅ Theoretical:
Azure VNet = private network. Subnets = segments. NSG = stateful firewall (allow/deny rules). Load Balancer (L4) for VMs. Application Gateway (L7) for HTTP/S — WAF, SSL offload, path-based routing. Private Endpoints = private access to PaaS (SQL, Storage). Peering = connect VNets.

### 💼 Real-Time Experience:
At **IU Health & Lanvera**:  
→ Designed **hub-spoke topology** — shared services in hub, apps in spokes.  
→ Used **NSGs** to restrict traffic — e.g., “web-tier only allows 443 from Internet”.  
→ Deployed **Application Gateway** with WAF — blocked OWASP Top 10 attacks.  
→ Used **Private Endpoints** for AKS → SQL DB, Blob Storage — no public exposure.  
→ Set up **VNet Peering** + **Azure Firewall** for cross-VNet communication.  
→ Reduced attack surface by 80%.

---

## 🔹 15. GCP Networking — VPC, Firewall, Cloud NAT, Load Balancer

### ❓ Q: How is GCP networking different? How did you configure it?

### ✅ Theoretical:
GCP VPC = global (not regional). Firewall Rules = stateful, applied at VPC level. Cloud NAT = egress for private VMs. Load Balancer = global anycast IP, L7 (HTTP/S) or L4 (TCP/UDP). Private Google Access = access Google APIs without public IP.

### 💼 Real-Time Experience:
At **IU Health**:  
→ Created **global VPCs** with subnets per region (us-central1, us-east1).  
→ Configured **Firewall Rules** — e.g., “allow 80/tcp from LB to VMs”.  
→ Used **Cloud NAT** for VMs in private subnets to download packages.  
→ Deployed **Global HTTP(S) LB** — pointed to GKE Ingress (NEGs).  
→ Enabled **Private Google Access** — VMs access Cloud Storage via internal IPs.  
→ Achieved 99.99% uptime with multi-region LB.

---

## 🔹 16. Azure Monitor, Log Analytics, Application Insights

### ❓ Q: How do you monitor Azure applications and infrastructure?

### ✅ Theoretical:
Azure Monitor = metrics + logs. Log Analytics = KQL queries on logs. Application Insights = APM for apps (requests, dependencies, exceptions). Alerts based on thresholds. Dashboards in Azure Portal or Grafana. Integrates with Logic Apps for auto-remediation.

### 💼 Real-Time Experience:
At **IU Health & Lanvera**:  
→ Configured **Azure Monitor Alerts** — CPU > 90% for 5m → Slack/email.  
→ Used **Log Analytics KQL** to find root cause of pod crashes — e.g., `ContainerLog | where LogEntry contains "OutOfMemory"`.  
→ Instrumented .NET apps with **Application Insights** — tracked slow DB calls, failed dependencies.  
→ Built **Grafana dashboards** pulling Azure Monitor metrics + Prometheus.  
→ Reduced MTTR from 4 hours → 30 mins.

---

## 🔹 17. GCP Operations (Stackdriver)

### ❓ Q: How do you monitor GCP environments?

### ✅ Theoretical:
GCP Operations (formerly Stackdriver) = metrics, logs, traces. Cloud Logging = structured logs. Cloud Monitoring = dashboards, alerts. Cloud Trace = distributed tracing. Integrates with Prometheus, Grafana. Alerting Policies → Pub/Sub → Slack/PagerDuty.

### 💼 Real-Time Experience:
At **IU Health**:  
→ Set up **Cloud Logging** — exported GKE pod logs to BigQuery for analysis.  
→ Created **Cloud Monitoring dashboards** — CPU, memory, HTTP errors per service.  
→ Configured **Alerting Policies** — “5xx errors > 1% for 5m” → PagerDuty.  
→ Used **Cloud Trace** — visualized latency in microservices chain.  
→ Integrated with **Grafana** for unified Azure + GCP dashboards.

---

## 🔹 18. ELK Stack (Elasticsearch, Logstash, Kibana)

### ❓ Q: Why did you deploy ELK Stack? How did you configure it?

### ✅ Theoretical:
ELK = Elasticsearch (search/analytics), Logstash (ingest/parse), Kibana (visualize). Centralizes logs from apps, infra, containers. Filebeat = lightweight shipper. Use cases: troubleshooting, security, compliance. Scalable — clusters for HA.

### 💼 Real-Time Experience:
At **IU Health & Lanvera**:  
→ Deployed **ELK on Azure VMs** — 3-node Elasticsearch cluster, Logstash, Kibana.  
→ Installed **Filebeat** on VMs + AKS pods — shipped logs to Logstash.  
→ Created **Kibana dashboards** — filtered by service, env, error level.  
→ Used for **security auditing** — e.g., “failed SSH attempts”.  
→ Replaced Splunk for cost savings — handled 10TB/day logs.

---

## 🔹 19. Grafana

### ❓ Q: How have you used Grafana for observability?

### ✅ Theoretical:
Grafana is open-source visualization tool — pulls metrics from Prometheus, Azure Monitor, Stackdriver, Elasticsearch. Dashboards with panels (graphs, tables, alerts). Supports templating, variables, annotations. Alerting → Slack, email, PagerDuty.

### 💼 Real-Time Experience:
At **IU Health & Lanvera**:  
→ Built **Grafana dashboards** correlating:  
  - Azure Monitor VM metrics + Prometheus K8s metrics + ELK app logs.  
→ Used **variables** — e.g., `$env = dev/stage/prod` to filter dashboards.  
→ Set **alert rules** — “pod restarts > 5 in 10m” → Slack.  
→ Shared dashboards with Dev/QA teams — improved collaboration.  
→ Reduced troubleshooting time by 50%.

---

## 🔹 20. Splunk

### ❓ Q: Have you used Splunk? For what use cases?

### ✅ Theoretical:
Splunk is enterprise log management — ingest, search, visualize machine data. Strong in security (SIEM), compliance. Expensive — often replaced by ELK for cost. Uses SPL (Search Processing Language). Dashboards, alerts, reports.

### 💼 Real-Time Experience:
At **Lanvera** (legacy systems):  
→ Ingested **Windows Event Logs**, **IIS logs**, **firewall logs** into Splunk.  
→ Created **dashboards** for security team — “failed logins by IP”.  
→ Set **alerts** — “brute force attack detected” → SOC team.  
→ Migrated to **ELK** for cost savings — retained Splunk only for compliance reports.

---

## 🔹 21. AppDynamics

### ❓ Q: What is AppDynamics? How did you use it?

### ✅ Theoretical:
AppDynamics is APM tool — monitors app performance (response time, throughput, errors). Traces business transactions — e.g., “checkout flow”. Identifies bottlenecks (slow DB, external calls). Integrates with infra monitoring.

### 💼 Real-Time Experience:
At **IU Health**:  
→ Instrumented **Java/.NET apps** with AppDynamics agents.  
→ Tracked **business transactions** — e.g., “patient registration → payment → confirmation”.  
→ Identified **slow SQL queries** — worked with DB team to optimize.  
→ Correlated with **Azure Monitor** — confirmed infra not bottleneck.  
→ Reduced checkout flow latency from 8s → 2s.

---

## 🔹 22. Python (Azure SDK, GCP Client Libraries)

### ❓ Q: Give an example of a Python script you wrote for automation.

### ✅ Theoretical:
Python is ideal for cloud automation — rich SDKs (azure-mgmt, google-cloud). Used for: provisioning, config, backups, monitoring. Libraries: requests, boto3 (AWS), azure-identity, google-auth. Schedule via cron, Azure Functions, Cloud Scheduler.

### 💼 Real-Time Experience:
At **IU Health**:  
→ Wrote **Python script** to auto-tag Azure resources:  
```python
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient

credential = DefaultAzureCredential()
client = ResourceManagementClient(credential, subscription_id)

for resource in client.resources.list():
    if "CreatedBy" not in resource.tags:
        client.tags.create_or_update_at_scope(
            scope=resource.id,
            parameters={"operation": "Merge", "properties": {"tags": {"CreatedBy": "Automation"}}}
        )
```
→ Ran weekly via **Azure Functions** — ensured compliance.  
→ Saved 10+ hours/week of manual tagging.

---

## 🔹 23. PowerShell

### ❓ Q: How have you used PowerShell in Azure automation?

### ✅ Theoretical:
PowerShell is Microsoft’s scripting language — ideal for Azure (Az modules). Used for: VM management, AD user provisioning, policy enforcement. Integrates with Azure Automation (runbooks), Jenkins.

### 💼 Real-Time Experience:
At **IU Health & Lanvera**:  
→ Wrote **PowerShell scripts** to:  
  - Bulk create Azure AD users from CSV — assign licenses, groups.  
  - Enforce naming conventions — `Get-AzResource | Where Name -notmatch "^[a-z0-9-]+$"`.  
→ Scheduled via **Azure Automation Runbooks** — e.g., nightly cleanup of unused disks.  
→ Integrated into **Jenkins** — e.g., `pwsh ./deploy.ps1 -env prod`.

---

## 🔹 24. Bash/Shell Scripting

### ❓ Q: Describe a Bash script you wrote for Linux systems.

### ✅ Theoretical:
Bash scripts automate Linux tasks: log rotation, backups, monitoring, deployments. Use cron for scheduling. Best practices: error handling, logging, idempotency. Integrates with CI/CD, config management.

### 💼 Real-Time Experience:
At **Microland & IU Health**:  
→ Wrote **Bash script** for log cleanup on RHEL VMs:  
```bash
#!/bin/bash
LOG_DIR="/var/log/app"
find $LOG_DIR -name "*.log" -mtime +30 -delete
df -h / | awk '{print $5}' | grep -o '[0-9]*' | while read usage; do
    if [ $usage -gt 90 ]; then
        echo "Disk > 90% - cleaning logs" | mail -s "Alert" admin@company.com
    fi
done
```
→ Ran daily via **cron** — prevented disk full incidents.  
→ Later replaced by **Azure Monitor Alerts** + **Automation Runbooks**.

---

## 🔹 25. Azure Active Directory (AD), RBAC, ADFS, SSO

### ❓ Q: How do you manage identity and access in Azure?

### ✅ Theoretical:
Azure AD = cloud identity. RBAC = assign roles (Owner, Contributor, Reader) to users/groups. Custom roles for least privilege. ADFS = federate on-prem AD. SSO = single sign-on for apps. Conditional Access = MFA, block risky logins.

### 💼 Real-Time Experience:
At **IU Health & Lanvera**:  
→ Created **custom RBAC roles** — e.g., “K8sDeployer” with only `Microsoft.ContainerService/managedClusters/write`.  
→ Configured **ADFS** — on-prem AD users access Azure Portal without new creds.  
→ Enforced **Conditional Access** — block logins from outside US or without MFA.  
→ Used **Managed Identities** for VMs/AKS → Key Vault — zero secrets in code.  
→ Reduced security incidents by 70%.

---

## 🔹 26. GCP IAM

### ❓ Q: How is GCP IAM different? How did you configure it?

### ✅ Theoretical:
GCP IAM = members (users, groups, service accounts) + roles (collections of permissions). Primitive roles (Owner, Editor, Viewer) vs custom. Service Accounts for apps. Workload Identity = let GKE pods impersonate SA. Policy = deny by default.

### 💼 Real-Time Experience:
At **IU Health**:  
→ Created **custom IAM roles** — e.g., “StorageViewerOnly” with only `storage.objects.get`.  
→ Used **Workload Identity** — GKE pods access Cloud Storage without keys.  
→ Assigned roles at **project/folder/org level** — least privilege.  
→ Audited with **IAM Recommender** — removed unused permissions.  
→ Achieved zero credential leaks.

---

## 🔹 27. Azure Key Vault

### ❓ Q: How do you secure secrets in Azure?

### ✅ Theoretical:
Azure Key Vault stores secrets (passwords, keys, certs). Access via RBAC or access policies. Integrates with apps (SDK), VMs (Managed Identity), pipelines (Service Connection). Soft-delete + purge protection for recovery. Audit logs.

### 💼 Real-Time Experience:
At **IU Health & Lanvera**:  
→ Stored **DB passwords, API keys, TLS certs** in Key Vault.  
→ Apps on VMs/AKS accessed via **Managed Identity** — no hardcoded secrets.  
→ Jenkins pipelines used **Service Connection** → injected as env vars.  
→ Enabled **soft-delete** — recovered accidentally deleted secret in 2 mins.  
→ Audited access with **Log Analytics** — “who accessed prod DB password?”.

---

## 🔹 28. Azure Functions / Cloud Functions

### ❓ Q: Describe a serverless function you built.

### ✅ Theoretical:
Serverless (Functions) = run code without managing infra. Event-driven — triggers (HTTP, timer, queue). Scales automatically. Pay per execution. Use cases: automation, webhooks, data processing.

### 💼 Real-Time Experience:
At **IU Health & Lanvera**:  
→ Built **Azure Function (Python)** triggered by **Blob Storage event** — resize uploaded images.  
→ Used **Event Grid** trigger — new VM created → tag it with “CreatedBy=Automation”.  
→ Scheduled **timer trigger** — nightly cleanup of temp files.  
→ Reduced cost by 70% vs always-on VM.  
→ Monitored with **Application Insights** — tracked execution time, failures.

---

## 🔹 29. Azure SQL Database / Cloud SQL

### ❓ Q: How do you manage cloud databases?

### ✅ Theoretical:
Managed DBs (Azure SQL, Cloud SQL) = automated patching, backup, scaling. Geo-replication for DR. Elastic pools (Azure) for cost. Private endpoints for security. Monitoring: DTU/CPU, deadlocks, long queries.

### 💼 Real-Time Experience:
At **IU Health & Lanvera**:  
→ Migrated on-prem SQL Server to **Azure SQL DB** using **DMS** — near-zero downtime.  
→ Used **elastic pools** — shared resources across dev/test DBs — 50% cost savings.  
→ Configured **Private Endpoints** — AKS pods access SQL via private IP.  
→ Set **alerts** — DTU > 80% → auto-scale.  
→ Achieved 99.99% uptime.

---

## 🔹 30. Azure Blob Storage / Cloud Storage

### ❓ Q: How do you use cloud storage for apps and backups?

### ✅ Theoretical:
Blob/Cloud Storage = object storage for unstructured data (logs, images, backups). Tiers: hot (frequent), cool (infrequent), archive (rare). Lifecycle policies for auto-tiering. Versioning, retention locks for compliance. CDN integration.

### 💼 Real-Time Experience:
At **IU Health & Lanvera**:  
→ Stored **app logs, VM snapshots, Terraform state** in Blob/Cloud Storage.  
→ Set **lifecycle policies** — move to archive after 90 days → 80% cost savings.  
→ Used **versioning** — recovered from accidental file deletion.  
→ Enabled **CDN** (Azure Front Door, Cloud CDN) for static assets — reduced latency by 60%.  
→ Secured with **Private Endpoints** + **RBAC**.

---

## 🔹 31. Azure Site Recovery (ASR) / GCP Migrate

### ❓ Q: How have you performed cloud migrations?

### ✅ Theoretical:
ASR replicates on-prem VMs to Azure — RPO < 5 mins. Cutover during maintenance window. GCP Migrate for Compute Engine. Database Migration Service (DMS) for SQL → Azure SQL. Test, validate, decommission on-prem.

### 💼 Real-Time Experience:
At **IU Health & Ksolves**:  
→ Used **Azure Migrate** to assess 200+ VMs — recommended sizing.  
→ Replicated with **ASR** — RPO < 5 mins.  
→ Migrated SQL Server to **Azure SQL DB** via **DMS** — 50+ TB, zero data loss.  
→ Cut over on weekend — validated apps → decommissioned on-prem.  
→ Migrated 50+ apps with 99.9% success.

---

## 🔹 32. Azure DevOps — Boards, Repos, Artifacts

### ❓ Q: How have you used Azure DevOps beyond Pipelines?

### ✅ Theoretical:
Azure DevOps = end-to-end DevOps:  
- **Boards** = Agile planning (sprints, backlogs).  
- **Repos** = Git repos with PRs, branch policies.  
- **Artifacts** = package feeds (NuGet, npm, Maven).  
Integrates with Pipelines — e.g., PR triggers build.

### 💼 Real-Time Experience:
At **Lanvera**:  
→ Used **Boards** for sprint planning — user stories, tasks, bugs.  
→ **Repos** with branch policies — PR requires 2 approvals + build success.  
→ **Artifacts** for NuGet packages — consumed by .NET apps.  
→ Full traceability — commit → build → release → work item.  
→ Improved team velocity by 30%.

---

## 🔹 33. Git, GitHub, GitLab

### ❓ Q: What branching strategy do you use? How do you enforce code quality?

### ✅ Theoretical:
GitFlow: `main` (prod), `develop` (staging), `feature/*` (dev). PRs/MRs for review. Branch policies: status checks (build, test, scan), required reviewers. Code quality: SonarQube, linters, pre-commit hooks.

### 💼 Real-Time Experience:
At **IU Health & Lanvera**:  
→ Used **GitFlow** — feature branches → develop → release → main.  
→ Enforced **PR reviews** + **status checks** (Jenkins build, SonarQube, Trivy).  
→ Blocked merges if coverage < 80% or critical bugs.  
→ Migrated from **SVN** to **Git** — trained teams.  
→ Reduced merge conflicts by 50%.

---

## 🔹 34. SonarQube

### ❓ Q: How do you integrate SonarQube into CI/CD?

### ✅ Theoretical:
SonarQube analyzes code for bugs, vulnerabilities, code smells, coverage. Integrates with build tools (Maven, Gradle) and CI (Jenkins). Quality Gates — fail build if conditions not met (e.g., coverage < 80%).

### 💼 Real-Time Experience:
At **Lanvera**:  
→ Added **SonarQube stage** in Jenkins:  
```groovy
stage('SonarQube') {
    steps {
        withSonarQubeEnv('SonarQube-Server') {
            sh 'mvn sonar:sonar'
        }
    }
}
stage('Quality Gate') {
    steps {
        timeout(time: 1, unit: 'HOURS') {
            def qg = waitForQualityGate()
            if (qg.status != 'OK') {
                error "Pipeline aborted: ${qg.status}"
            }
        }
    }
}
```
→ Blocked PRs with < 80% coverage or critical bugs.  
→ Reduced tech debt by 60% in 6 months.

---

## 🔹 35. Trivy / Checkov

### ❓ Q: How do you scan for vulnerabilities in containers and IaC?

### ✅ Theoretical:
**Trivy** scans container images for CVEs. **Checkov** scans IaC (Terraform, ARM) for misconfigs (e.g., public S3 bucket). Integrate into CI — fail build on critical findings. Shift left — catch issues early.

### 💼 Real-Time Experience:
At **Lanvera & IU Health**:  
→ Added **Trivy scan** in Jenkins — `trivy image --exit-code 1 --severity CRITICAL myapp:latest`.  
→ Scanned **Terraform** with **Checkov** — `checkov -d . --framework terraform`.  
→ Blocked pipelines on critical CVEs or “public storage bucket” misconfigs.  
→ Reduced critical vulnerabilities by 90%.

---

## 🔹 36. Blue-Green / Canary Deployments

### ❓ Q: How have you implemented zero-downtime deployments?

### ✅ Theoretical:
**Blue-Green**: Two identical envs — switch traffic from old (blue) to new (green). Instant rollback.  
**Canary**: Roll out to small % of users → monitor → ramp up. Low risk.  
Tools: Istio, Spinnaker, Argo Rollouts, Azure Traffic Manager.

### 💼 Real-Time Experience:
At **Lanvera**:  
→ **Blue-Green** for .NET apps on **Azure App Services** — used **deployment slots**. Swap on approval.  
→ **Canary** on AKS with **Istio** — 5% traffic → 25% → 100% over 1 hour.  
→ Monitored with **Application Insights** — auto-rollback if error rate > 1%.  
→ Achieved **zero-downtime** — zero user impact during releases.

---

## 🔹 37. Azure Policy / GCP Organization Policy

### ❓ Q: How do you enforce governance in cloud?

### ✅ Theoretical:
**Azure Policy** = enforce rules (e.g., “all storage must be encrypted”). **GCP Org Policy** = similar. Assign at management group/org level. Audit or deny non-compliant resources. Remediate automatically.

### 💼 Real-Time Experience:
At **IU Health**:  
→ Created **Azure Policy** — “deny public Blob Storage” — blocked manual creation.  
→ **GCP Org Policy** — “require VPC Service Controls for Cloud Storage”.  
→ Assigned at **subscription/folder level**.  
→ Used **remediation tasks** — auto-fixed non-compliant resources.  
→ Achieved 100% compliance in audits.

---

## 🔹 38. Azure Backup / Site Recovery

### ❓ Q: How do you ensure business continuity?

### ✅ Theoretical:
**Azure Backup** = backup VMs, files, DBs. Retention policies. **Site Recovery (ASR)** = replicate VMs to secondary region for DR. RPO (recovery point objective), RTO (recovery time objective). Test failover.

### 💼 Real-Time Experience:
At **IU Health & Lanvera**:  
→ Configured **Azure Backup** for VMs — daily backups, 30-day retention.  
→ Used **ASR** for on-prem → Azure replication — RPO < 5 mins.  
→ Tested **failover** quarterly — validated apps in DR region.  
→ Reduced RTO from 24 hours → 1 hour.

---

## 🔹 39. Azure DNS / Cloud DNS

### ❓ Q: How do you manage DNS in cloud?

### ✅ Theoretical:
Azure DNS / Cloud DNS = host DNS zones in cloud. Create records (A, CNAME, MX). Integrates with domains (GoDaddy, etc.). Traffic routing, health checks (Traffic Manager, Cloud Load Balancer).

### 💼 Real-Time Experience:
At **IU Health & Lanvera**:  
→ Hosted **internal/external zones** in Azure DNS — e.g., `app.internal`, `www.company.com`.  
→ Used **CNAME records** for CDN, LB.  
→ Integrated with **Azure Traffic Manager** for geo-routing.  
→ Reduced DNS propagation time from hours → seconds.

---

## 🔹 40. Azure Front Door / Cloud CDN

### ❓ Q: How do you reduce latency for global users?

### ✅ Theoretical:
**Azure Front Door** = global HTTP load balancer + WAF + CDN. **Cloud CDN** = caches content at edge. Reduces latency, offloads origin. Configure caching rules, compression, geo-filtering.

### 💼 Real-Time Experience:
At **IU Health & Lanvera**:  
→ Pointed **Front Door/Cloud CDN** to Blob Storage/App Services.  
→ Set **caching rules** — cache static assets for 1 day.  
→ Enabled **compression** — reduced bandwidth by 60%.  
→ Used **geo-filtering** — blocked traffic from high-risk countries.  
→ Reduced latency from 500ms → 50ms for global users.

---
