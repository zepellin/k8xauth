# Usage with ArgoCD

## Installation

For the usage with ArgoCD the binary has to be available in the `argocd-server` and `argocd-application-controller` deployments/pods.

The binary can be installed via [custom ArgoCD images](https://argo-cd.readthedocs.io/en/stable/operator-manual/custom_tools/#byoi-build-your-own-image), or [added via volume mounts](https://argo-cd.readthedocs.io/en/stable/operator-manual/custom_tools/#adding-tools-via-volume-mounts) and placed in the `argocd-server` and `argocd-application-controller` deployments/pods.

### Option 1: Image Volume (Kubernetes 1.35+)

On Kubernetes 1.35+ clusters you can use an [image volume](/docs/image-volumes.md) to mount the binary directly — no init containers or network downloads required.

Example for [ArgoCD official Helm Chart](https://github.com/argoproj/argo-helm/blob/main/charts/argo-cd/values.yaml#L655-L675):

```yaml
controller and server:
  ...
  volumeMounts:
   - mountPath: /usr/local/bin/k8xauth
     name: k8xauth
     subPath: k8xauth

  volumes:
   - name: k8xauth
     image:
       reference: ghcr.io/zepellin/k8xauth:v0.2.2
       pullPolicy: IfNotPresent
```

### Option 2: Init Container

For clusters running Kubernetes < 1.35, use an init container to download the binary:

Example for [ArgoCD official Helm Chart](https://github.com/argoproj/argo-helm/blob/main/charts/argo-cd/values.yaml#L655-L675):

```yaml
controller and server:
  ...
  initContainers:
   - name: download-tools
     image: alpine:3
     command: [sh, -c]
     args:
       - wget -qO k8xauth https://github.com/zepellin/k8xauth/releases/download/v0.1.6/k8xauth-v0.1.6-linux-amd64 && chmod +x k8xauth && mv k8xauth /argo-k8xauth/
     volumeMounts:
       - mountPath: /argo-k8xauth
         name: argo-k8xauth

  volumeMounts:
   - mountPath: /usr/local/bin/k8xauth
     name: argo-k8xauth
     subPath: k8xauth

  volumes:
   - name: argo-k8xauth
     emptyDir: {}
```

## Usage

ArgoCD can be configured to use exec provider to fetch credentials for external clusters by creating a kubernetes secret with target cluster and exec plugin configuration.

### EKS cluster

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-eks-cluster-name-secret
  labels:
    argocd.argoproj.io/secret-type: cluster
type: Opaque
stringData:
  name: my-eks-cluster-name
  server: https://213456423213456789456123ABCDEF.grx.us-east-1.eks.amazonaws.com
  config: |
    {
      "execProviderConfig": {
        "command": "k8xauth",
        "args": [
            "eks",
            "--rolearn",
            "arn:aws:iam::123456789012:role/argocdrole",
            "--cluster",
            "my-eks-cluster-name",
            "--stsregion",
            "us-east-2"
        ],
        "apiVersion": "client.authentication.k8s.io/v1beta1",
        "installHint": "k8xauth missing. For installation follow https://github.com/zepellin/k8xauth"
      },
      "tlsClientConfig": {
        "insecure": false,
        "caData": "base64_encoded_ca_data"
      }
    }
```

### GKE cluster

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-gke-cluster-name-secret
  labels:
    argocd.argoproj.io/secret-type: cluster
type: Opaque
stringData:
  name: my-gke-cluster-name
  server: https://192.0.2.1
  config: |
    {
      "execProviderConfig": {
        "command": "k8xauth",
        "args": [
            "gke",
            "--projectid",
            "123456789012",
            "--poolid",
            "my-wli-fed-pool-id",
            "--providerid",
            "my-wli-fed-provider-id"
        ],
        "apiVersion": "client.authentication.k8s.io/v1beta1",
        "installHint": "k8xauth missing. For installation follow https://github.com/zepellin/k8xauth"
      },
      "tlsClientConfig": {
        "insecure": false,
        "caData": "base64_encoded_ca_data"
      }
    }
```

### AKS cluster

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-aks-cluster-name-secret
  labels:
    argocd.argoproj.io/secret-type: cluster
type: Opaque
stringData:
  name: my-aks-cluster-name
  server: https://192.0.2.2
  config: |
    {
      "execProviderConfig": {
        "command": "k8xauth",
        "args": [
            "aks",
            "--tenantid",
            "12345678-1234-1234-1234-123456789abc",
            "--clientid",
            "12345678-1234-1234-1234-123456789abc"
        ],
        "apiVersion": "client.authentication.k8s.io/v1beta1",
        "installHint": "k8xauth missing. For installation follow https://github.com/zepellin/k8xauth"
      },
      "tlsClientConfig": {
        "insecure": false,
        "caData": "base64_encoded_ca_data"
      }
    }
```

### Generic OIDC target

Use this when the destination cluster or API server accepts the source OIDC token directly and does not require any cloud-provider specific exchange.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-generic-oidc-cluster-secret
  labels:
    argocd.argoproj.io/secret-type: cluster
type: Opaque
stringData:
  name: my-generic-oidc-cluster
  server: https://192.0.2.10
  config: |
    {
      "execProviderConfig": {
        "command": "k8xauth",
        "args": [
            "generic-oidc",
            "--authsource",
            "gke",
            "--audience",
            "my-target-audience"
        ],
        "apiVersion": "client.authentication.k8s.io/v1beta1",
        "installHint": "k8xauth missing. For installation follow https://github.com/zepellin/k8xauth"
      },
      "tlsClientConfig": {
        "insecure": false,
        "caData": "base64_encoded_ca_data"
      }
    }
```
