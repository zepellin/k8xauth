# Usage with ArgoCD

## Installation

For the usage with ArgoCD the binary has to be available in the `argocd-server` and `argocd-application-controller` deployments/pods.

The binary can be installed via [custom ArgoCD images](https://argo-cd.readthedocs.io/en/stable/operator-manual/custom_tools/#byoi-build-your-own-image), or [added via volume mounts](https://argo-cd.readthedocs.io/en/stable/operator-manual/custom_tools/#adding-tools-via-volume-mounts) and placed in the `argocd-server` and `argocd-application-controller` deployments/pods.

Example for [ArgoCD official Helm Chart](https://github.com/argoproj/argo-helm/blob/main/charts/argo-cd/values.yaml#L655-L675):

```yaml
controller and server:
  ...
  initContainers:
   - name: download-tools
     image: alpine:3
     command: [sh, -c]
     args:
       - wget -qO k8xauth https://github.com/trhyo/k8xauth/releases/download/v0.1.3/k8xauth-v0.1.3-linux-amd64 && chmod +x k8xauth && mv k8xauth /argo-k8xauth/
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
        "installHint": "k8xauth missing. For installation follow https://github.com/trhyo/k8xauth"
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
        "installHint": "k8xauth missing. For installation follow https://github.com/trhyo/k8xauth"
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
        "installHint": "k8xauth missing. For installation follow https://github.com/trhyo/k8xauth"
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
        "installHint": "k8xauth missing. For installation follow https://github.com/trhyo/k8xauth"
      },
      "tlsClientConfig": {
        "insecure": false,
        "caData": "base64_encoded_ca_data"
      }
    }
```
