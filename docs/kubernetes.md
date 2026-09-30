# Kubernetes service account token source authentication

This document covers using a Kubernetes service account token as the source identity. This lets `k8xauth` running in any Kubernetes cluster (self-managed, on premise or on any cloud provider) retrieve credentials for AWS EKS, Google Cloud GKE or Azure AKS clusters, using the source cluster's own OIDC issuer for federation.

## Source authentication

The `kubernetes` source reads a service account token from a file and uses it as the OIDC identity token for the target provider exchange. It must be selected explicitly with `--authsource kubernetes`.

> [!NOTE]
> The `kubernetes` source is not included in `--authsource all` (the default). The default service account token is present in almost every pod, including those running on GKE, EKS or AKS, so trying it automatically would silently mask a misconfigured cloud provider source and fail later with a less clear token exchange error.

* **--sourcetokenfile**: Path of the service account token file (optional, default: `/var/run/secrets/kubernetes.io/serviceaccount/token`).

The session identifier (used e.g. as the AWS role session name) is derived from the name of the pod the token is bound to.

### Prerequisites

1. The source cluster's service account issuer must be reachable by the target cloud provider. The issuer is set using the kube-apiserver `--service-account-issuer` flag (e.g. `https://oidc.example.com/my-cluster`), and its discovery document and signing keys (`kubectl get --raw /.well-known/openid-configuration` and `kubectl get --raw /openid/v1/jwks`) must be published at `<issuer>/.well-known/openid-configuration` and the `jwks_uri` it references (set using `--service-account-jwks-uri`). A public object storage bucket is a common way of hosting these. Google Cloud can alternatively be given the signing keys directly (see below).
2. A service account token projected with an audience accepted by the target provider. The default service account token uses the API server's audience, so a dedicated projected token is recommended:

    ```yaml
    spec:
      serviceAccountName: argocd-application-controller
      containers:
        - name: app
          volumeMounts:
            - name: k8xauth-token
              mountPath: /var/run/secrets/k8xauth
              readOnly: true
      volumes:
        - name: k8xauth-token
          projected:
            sources:
              - serviceAccountToken:
                  path: token
                  audience: sts.amazonaws.com
                  expirationSeconds: 3600
    ```

    and passed to `k8xauth` using `--sourcetokenfile /var/run/secrets/k8xauth/token`.

The token subject has the format `system:serviceaccount:<namespace>:<service account name>`.

### AWS EKS target

1. An [IAM OIDC identity provider](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html) for the source cluster issuer URL with the projected token audience (e.g. `sts.amazonaws.com`).
2. An AWS role trusting the OIDC provider from step 1. Example:

    ```json
    "Statement": [ {
        "Effect": "Allow",
        "Principal": {
            "Federated": "arn:aws:iam::012345678910:oidc-provider/oidc.example.com/my-cluster"
        },
        "Action": "sts:AssumeRoleWithWebIdentity",
        "Condition": {
            "StringEquals": {
                "oidc.example.com/my-cluster:aud": "sts.amazonaws.com",
                "oidc.example.com/my-cluster:sub": "system:serviceaccount:argocd:argocd-application-controller"
            }
        }
    }]
    ```

3. The IAM role from step 2. having appropriate permissions for EKS cluster(s) management. See [EKS usage](/docs/eks.md#usage).

### Google Cloud GKE target

1. A Workload Identity Federation pool with an OIDC provider for the source cluster issuer:

    ```bash
    gcloud iam workload-identity-pools providers create-oidc "gcp-fed-provider-id" \
    --location="global" \
    --workload-identity-pool="gcp-fed-pool-id" \
    --issuer-uri="https://oidc.example.com/my-cluster" \
    --attribute-mapping="google.subject=assertion.sub"
    ```

    If the issuer is not publicly reachable, the signing keys can be uploaded instead by adding `--jwk-json-path` pointing to the output of `kubectl get --raw /openid/v1/jwks`.
2. The projected token audience set to the provider's default allowed audience, `https://iam.googleapis.com/projects/<project number>/locations/global/workloadIdentityPools/<pool id>/providers/<provider id>`, or to a custom audience configured using `--allowed-audiences`.
3. Optionally, a Google Cloud service account granting `Workload Identity User` role to `principal://iam.googleapis.com/projects/<project number>/locations/global/workloadIdentityPools/<pool id>/subject/system:serviceaccount:<namespace>:<service account name>`, if `--serviceaccount` parameter is used.
4. Federated identity or Google Cloud service account having appropriate permissions to manage GKE cluster. See [GKE usage](/docs/gke.md#usage).

### Azure AKS target

1. An Azure user assigned managed identity or Entra app with a federated credential for the source cluster issuer:

    ```bash
    az identity federated-credential create --name "k8xauth" \
    --identity-name "my-managed-identity" \
    --resource-group "my-resource-group" \
    --issuer "https://oidc.example.com/my-cluster" \
    --subject "system:serviceaccount:argocd:argocd-application-controller" \
    --audiences "api://AzureADTokenExchange"
    ```

2. The projected token audience set to the federated credential audience (e.g. `api://AzureADTokenExchange`).
3. Appropriate permissions given to the managed identity from step 1. to connect to target AKS cluster. See [AKS usage](/docs/aks.md#usage).

## Usage

Examples:

```bash
k8xauth eks --authsource "kubernetes" --sourcetokenfile "/var/run/secrets/k8xauth/token" \
--rolearn "arn:aws:iam::123456789012:role/argocd-platform" \
--cluster "my-cluster-name"

k8xauth gke --authsource "kubernetes" --sourcetokenfile "/var/run/secrets/k8xauth/token" \
--projectid "12345678901" \
--poolid "gcp-fed-pool-id" \
--providerid "gcp-fed-provider-id"

k8xauth aks --authsource "kubernetes" --sourcetokenfile "/var/run/secrets/k8xauth/token" \
--tenantid "12345678-1234-1234-1234-123456789abc" \
--clientid "12345678-1234-1234-1234-123456789abc"
```

The token audience is fixed by the token projection. When `--audience` is passed to the `generic-oidc` command, it is checked against the token audience rather than requested, and the source fails if the token does not include it.
