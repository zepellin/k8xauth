# Generic OIDC ExecCredential output

This document covers the case of retrieving a generic OIDC ExecCredential from AWS EKS, Azure AKS, or Google Cloud GKE source identities without performing any cloud-provider specific token exchange.

## Source authentication

The `generic-oidc` command uses the same source authentication mechanisms as the provider-specific commands:

1. Google Cloud GKE or GCE via Workload Identity
2. AWS EKS via IRSA
3. Azure AKS via Workload Identity

By default, `k8xauth` tries all supported sources sequentially. To constrain lookup to a single source, pass `--authsource gke`, `--authsource eks`, or `--authsource aks`.

## Usage

* **--audience**: Audience or scope to request for the source token when the source supports it (optional).
* **--authsource**: Authentication source to use for retrieving the token (optional, default: `all`).

Example:

```bash
k8xauth generic-oidc --authsource "gke"

k8xauth generic-oidc --authsource "aks" --audience "api://custom-app/.default"
```

## Audience behavior

When `--audience` is not specified, the command keeps the current source-specific defaults:

* **GKE**: Requests an identity token with audience `gcp`.
* **AKS**: Requests a token for scope `api://AzureADTokenExchange/.default`.
* **EKS**: Uses the projected IRSA token as provided by Kubernetes. The audience is controlled by the service account token projection, not by `k8xauth` at runtime.

## Output

The command writes a Kubernetes [ExecCredential](https://kubernetes.io/docs/reference/config-api/client-authentication.v1beta1/#client-authentication-k8s-io-v1beta1-ExecCredential) object to standard output. The `status.token` field contains the source token without any transformation.

This is useful when the target system expects a plain OIDC bearer token and does not require an AWS, Azure, or Google Cloud specific exchange flow.

## With kubectl

Kubectl can be configured to use `generic-oidc` directly as an exec credential plugin when the target cluster accepts the source OIDC token.

```yaml
users:
- name: generic-oidc-cluster
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
			interactiveMode: IfAvailable
			provideClusterInfo: true
```