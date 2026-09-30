# Authentication with Azure AKS clusters

This document covers the case of retrieving Kubernetes credentials for an Azure AKS cluster from AWS EKS or Google Cloud GKE environments.

## Source authentication

### Prerequisites for AWS EKS source authentication

For this application running on a AWS EKS cluster

1. AWS IRSA ([IAM for service accounts](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html)) configured for the service used by the pod running this application.
2. Azure user assigned managed identity or Entra app with federated credential set up with EKS cluster issuer (format `https://oidc.eks.us-east-2.amazonaws.com/id/<id>`) and desired allowed audiences
3. Appropriate permissions given to the entra managed identity from step 2. to connect to target AKS cluster.

### Prerequisites for GKE source authentication

For this application running on a Google Cloud GKE cluster/GCE VM:

1. A Google Cloud environment configured with IAM identity. This could be a VM instance using a service account identity or a GKE pod configured with GKE workload identity. Workload identity can be easily configured using the official workload identity [terraform module](https://registry.terraform.io/modules/terraform-google-modules/kubernetes-engine/google/latest/submodules/workload-identity).
2. Azure user assigned managed identity or Entra app with federated credential set up with Google Cloud service account identity (issuer `https://accounts.google.com`, subject identifier - service account numerical ID) and desired allowed audiences
3. Appropriate permissions given to the entra managed identity from step 2. to connect to target AKS cluster.

### Prerequisites for Kubernetes service account source authentication

For this application running on any Kubernetes cluster, using its service account token and OIDC issuer, see [Kubernetes source authentication](/docs/kubernetes.md). This source is not part of the default `--authsource all` and must be selected with `--authsource kubernetes`.

## Usage

* **--clientid**: Azure Managed Principal/App client ID (required).
* **--tenantid**: Azure Entra Directory tenant ID (required).
* **--serverid**: Azure Entra (AAD) server app ID (optional, default: `6dae42f8-4368-4678-94ff-3960e28e3630`).

Example:

```bash
k8xauth aks --tenantid "12345678-1234-1234-1234-123456789abc" --clientid "12345678-1234-1234-1234-123456789abc"
```
