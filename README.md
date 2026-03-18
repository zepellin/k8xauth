# Kubernetes cross-cloud credentials provider (k8xauth)

The purpose of this application is to facilitate identity based authentication (without use of any permanents/long term credentials) of managed kuberenetes clusters ([GKE](https://cloud.google.com/kubernetes-engine?hl=en), [EKS](https://aws.amazon.com/eks/), [AKS](https://azure.microsoft.com/en-us/products/kubernetes-service)) across different cloud providers. The application can be used for cases such as `kubectl` user authentication, ArgoCD [external cluster authentication](https://argo-cd.readthedocs.io/en/release-1.8/operator-manual/declarative-setup/#clusters) or Kubernetes Go SDK out of cluster authentication.

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Installation](#installation)
- [Building](#building)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)

## Introduction

With number of services and applications running on multiple cloud providers and to allow for better security practices when setting up authentication, the goal of this project is to allow identity based authentication between different cloud providers. This is achieved by using Federated authentication mechanism available for each supported cloud provider (Google Cloud/GKE - Workload Identity Federation, AWS/EKS - IAM OIDC Federation, Azure/AKS - Federated Credentials)

## Features

A scenario this application covers is an application/kuberentes client (such as ArgoCD instance) running in a Kubernetes cluster on a Cloud provider A. and using available identity federation mechanism to retrieve credentials from cluster in a different cloud provider B.

The output of the program is an [ExecCredential](https://kubernetes.io/docs/reference/config-api/client-authentication.v1beta1/#client-authentication-k8s-io-v1beta1-ExecCredential) object of the [client.authentication.k8s.io/v1beta1](https://kubernetes.io/docs/reference/config-api/client-authentication.v1beta1/) Kubernetes API that is consumed by a Kubernetes client (ArgoCD, `kubectl`, etc) when authenticating with target Kubernetes cluster.

Currently this application supports AWS, Azure and Google Cloud Platform, with following authentication combinations possible:

- **AWS/EKS** using [IRSA](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html) ([instructions](/docs/eks.md)) to:
  - GCP/GKE via [Workload Identity Federation](https://cloud.google.com/iam/docs/workload-identity-federation)
  - Azure/AKS via [Federated Credentials](https://azure.github.io/azure-workload-identity/docs/topics/federated-identity-credential.html#federated-identity-credential-for-a-user-assigned-managed-identity-1)
- **Azure/AKS** using [Workload Identity](https://learn.microsoft.com/en-us/azure/aks/workload-identity-overview?tabs=dotnet) ([instructions](/docs/aks.md)) to:
  - AWS/EKS via IAM role [OIDC trust policy](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html)
  - GCP/GKE via [Workload Identity Federation](https://cloud.google.com/iam/docs/workload-identity-federation)
- **Google Cloud/GKE** using [Workload Identity](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity) ([instructions](/docs/gke.md)) to:
  - AWS/EKS via IAM role [OIDC trust policy](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html)
  - Azure/AKS via [Federated Credentials](https://azure.github.io/azure-workload-identity/docs/topics/federated-identity-credential.html#federated-identity-credential-for-a-user-assigned-managed-identity-1)

The same source identities can also be used to emit a generic OIDC ExecCredential without any provider-specific exchange. See [generic OIDC usage](/docs/generic-oidc.md).

### Installation

Download precompiled binary for your platform from the repository' [releases page](https://github.com/trhyo/k8xauth/releases).

### Usage

#### Authentication

The application uses credentials provided by the environment it is running in (Workload Identity for GKE and AKS, IRSA for EKS). By default all authentication methods are tried sequentially. Optionally for all commands `--authsource` parameter might be specified which will set authentication source to only selected one (possible options `gke`, `eks`, `aks` or `all`). If not specified, `all` is used which will try all source authentication methods.

> [!TIP]
> For debugging purposes and to aid with authentication federation setup, the application can be configured to print source authentication token using the `--printsourceauthtoken` parameter.

#### Target system parameters

The application uses target cloud provider options specified as the application parameters.

Examples:

```bash
# Fetch GKE credentials
k8xauth gke \
--projectid "12345678901" \
--poolid "gcp-fed-pool-id" \
--providerid "gcp-fed-provider-id" \
--serviceaccount "gcp-sa-name@gcp-project-name.iam.gserviceaccount.com"

# Fetch EKS credentials
k8xauth eks \
--rolearn "arn:aws:iam::123456789012:role/argocd-platform" \
--stsregion "us-east-2" \
--cluster "my-cluster-name"

# Fetch AKS credentials
k8xauth aks \
--tenantid "12345678-1234-1234-1234-123456789abc" \
--clientid "12345678-1234-1234-1234-123456789abc"

# Fetch generic OIDC credentials
k8xauth generic-oidc \
--authsource "gke"

# Fetch generic OIDC credentials with a custom audience
k8xauth generic-oidc \
--authsource "aks" \
--audience "api://custom-app/.default"
```

The `generic-oidc` command returns the source OIDC token as-is in an ExecCredential object. When `--audience` is omitted, the existing source defaults are preserved:

- GKE source defaults to audience `gcp`
- AKS source defaults to scope `api://AzureADTokenExchange/.default`
- EKS source uses the projected IRSA token as provided by Kubernetes

#### With kubectl

Kubectl can be configured to use exec credential plugin:

```yaml
...
- name: cluster_name
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      args:
        - "--rolearn",
        - "arn:aws:iam::123456789012:role/argocdrole",
        - "--cluster",
        - "my-eks-cluster-name",
        - "--stsregion",
        - "us-east-2"
      command: k8xauth
      env: null
      installHint: "k8xauth missing. For installation follow https://github.com/trhyo/k8xauth#installation"
      interactiveMode: IfAvailable
      provideClusterInfo: true
...
```

For a generic OIDC destination that accepts the source token directly:

```yaml
...
- name: generic_oidc_cluster
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: k8xauth
      args:
        - generic-oidc
        - --authsource
        - gke
        - --audience
        - my-target-audience
      env: null
      installHint: "k8xauth missing. For installation follow https://github.com/trhyo/k8xauth#installation"
      interactiveMode: IfAvailable
      provideClusterInfo: true
...
```

#### With ArgoCD

ArgoCD can be configured to exec plugins for retrieving external cluster credentials, for more detailed instruction please refer to [usage with ArgoCD](/docs/argocd.md) documentation.

### Building

This is a Golang application and can be built using standard build process:

```bash
env GOOS=target-OS GOARCH=target-architecture go build .
```

## Contributing

If you'd like to contribute to this project, please follow the standard open-source contribution guidelines. Please report issues, submit feature requests, or create pull requests to improve the application.

## License

This project is licensed under Apache License 2.0 - see [LICENSE](LICENSE) file for details.
