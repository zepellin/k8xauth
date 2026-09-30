# Generic OIDC ExecCredential output

This document covers the case of retrieving a generic OIDC ExecCredential from AWS EKS, Azure AKS, Google Cloud GKE, or Kubernetes service account source identities without performing any cloud-provider specific token exchange.

## Source authentication

The `generic-oidc` command uses the same source authentication mechanisms as the provider-specific commands:

1. Google Cloud GKE or GCE via Workload Identity
2. AWS EKS via IRSA
3. Azure AKS via Workload Identity
4. Any Kubernetes cluster via a service account token file ([instructions](/docs/kubernetes.md))

By default, `k8xauth` tries the GKE, EKS and AKS sources sequentially. To constrain lookup to a single source, pass `--authsource gke`, `--authsource eks`, or `--authsource aks`. The Kubernetes source is not included in the default `all` lookup and must be selected with `--authsource kubernetes`.

## Usage

* **--audience**: Audience or scope to request for the source token when the source supports it (optional).
* **--authsource**: Authentication source to use for retrieving the token (optional, default: `all`).
* **--sourcetokenfile**: Service account token file used by the `kubernetes` source (optional, default: `/var/run/secrets/kubernetes.io/serviceaccount/token`).

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
* **Kubernetes**: Uses the service account token file as provided by Kubernetes. The audience is controlled by the token projection; if `--audience` is specified, the token must include it.

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