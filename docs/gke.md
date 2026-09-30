# Authentication with Google Cloud GKE clusters

This document covers the case of retrieving Kubernetes credentials for an Google Cloud GKE cluster from AWS EKS or Azure AKS environments.

## Source authentication

### Prerequisites for AWS EKS source authentication

For this application running on a AWS EKS cluster

1. AWS IRSA ([IAM for service accounts](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html)) configured for the service used by the pod running this application.
2. Google Cloud Workload Identity Federation set up with EKS cluster OIDC issuer (format `https://oidc.eks.us-east-2.amazonaws.com/id/<id>`) and optional parameters for allowed audience.
3. Optionally, a Google Cloud service account with `Workload Identity User` permission, if `--serviceaccount` parameter is used.
4. Federated identity (in the form of `principal://..`) or Google Cloud service account having appropriate permissions to manage GKE cluster.

### Prerequisites for Azure AKS source authentication

For this application running on a Azure AKS cluster:

1. An Azure Entra object (such as user assigned managed identity) with [Workload Identity set up](https://azure.github.io/azure-workload-identity/docs/quick-start.html) for the Kubernetes service account this application' pod is set up to use.
2. Google Cloud Workload Identity Federation set up with Azure Entra tenant issuer (format `https://login.microsoftonline.com/f598b8e2-04c4-4143-86cc-5ba3b23a03ea/v2.0`) and allowed audience(s)
3. Optionally, a Google Cloud service account with `Workload Identity User` permission, if `--serviceaccount` parameter is used.
4. Federated identity (in the form of `principal://..`) or Google Cloud service account having appropriate permissions to manage GKE cluster.

### Prerequisites for Kubernetes service account source authentication

For this application running on any Kubernetes cluster, using its service account token and OIDC issuer, see [Kubernetes source authentication](/docs/kubernetes.md). This source is not part of the default `--authsource all` and must be selected with `--authsource kubernetes`.

## Usage

* **--projectid**: Numerical GCP project ID (required).
* **--poolid**: GCP Worload Identity Federation pool ID (required).
* **--providerid**: GCP Worload Identity Federation provider ID (optional, default: us-east-1).
* **--serviceaccount**: GCP Service Account to generate access token for (optional).

Example:

```bash
k8xauth gke --projectid "12345678901" --poolid "gcp-fed-pool-id" --providerid "gcp-fed-provider-id" --serviceaccount "gcp-sa-name@gcp-project-name.iam.gserviceaccount.com"
```
