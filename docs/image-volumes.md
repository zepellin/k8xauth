# Using k8xauth with Kubernetes Image Volumes

## Overview

Starting with Kubernetes 1.35, [Image Volumes](https://kubernetes.io/docs/concepts/storage/volumes/#image) are generally available. Image volumes allow you to mount an OCI image directly as a read-only volume inside a pod — without needing init containers, `emptyDir` volumes, or `wget` scripts.

The `k8xauth` binary is published as a minimal (`FROM scratch`) multi-architecture OCI image to GitHub Container Registry on every release:

```text
ghcr.io/zepellin/k8xauth:<version>   (e.g. ghcr.io/zepellin/k8xauth:v0.2.4)
ghcr.io/zepellin/k8xauth:latest
```

Supported platforms: `linux/amd64`, `linux/arm64`.

## Requirements

- Kubernetes **1.35+** (the `ImageVolume` feature gate is GA and enabled by default)
- The container runtime must support OCI image volumes (containerd 2.0+, CRI-O 1.31+)

## Usage

### Pod spec

Mount the image as a volume and reference the binary via `subPath`:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: example
spec:
  containers:
    - name: app
      image: my-app:latest
      volumeMounts:
        - name: k8xauth
          mountPath: /usr/local/bin/k8xauth
          subPath: k8xauth
  volumes:
    - name: k8xauth
      image:
        reference: ghcr.io/zepellin/k8xauth:v0.2.4
        pullPolicy: IfNotPresent
```

The binary is located at `/k8xauth` inside the image. Using `subPath: k8xauth` mounts only the binary into the container at the specified `mountPath`.

### Deployment / StatefulSet

The same volume definition works in any workload resource:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-controller
spec:
  template:
    spec:
      containers:
        - name: controller
          image: my-controller:latest
          volumeMounts:
            - name: k8xauth
              mountPath: /usr/local/bin/k8xauth
              subPath: k8xauth
      volumes:
        - name: k8xauth
          image:
            reference: ghcr.io/zepellin/k8xauth:v0.2.4
            pullPolicy: IfNotPresent
```

### ArgoCD with Image Volumes

For ArgoCD-specific examples using image volumes instead of init containers, see [Usage with ArgoCD](/docs/argocd.md).

## Image Signature Verification

Every release image is signed using [Sigstore cosign](https://docs.sigstore.dev/cosign/overview/) keyless signing with the GitHub Actions OIDC identity. This allows you to verify the image provenance before use.

### Verify manually with cosign

```bash
cosign verify \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp https://github.com/zepellin/k8xauth/ \
  ghcr.io/zepellin/k8xauth:v0.2.4
```

### Verify automatically with Kyverno

Apply a `ClusterPolicy` to enforce that only signed `k8xauth` images (including image volumes) are admitted:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-k8xauth-image
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: verify-k8xauth-signature
      match:
        any:
          - resources:
              kinds:
                - Pod
      verifyImages:
        - imageReferences:
            - "ghcr.io/zepellin/k8xauth:*"
          attestors:
            - entries:
                - keyless:
                    issuer: https://token.actions.githubusercontent.com
                    subjectRegExp: https://github.com/zepellin/k8xauth/.*
                    rekor:
                      url: https://rekor.sigstore.dev
```

> [!NOTE]
> Kyverno 1.12+ supports verifying signatures on images referenced in `volumes[].image.reference` (image volumes), not only container images. Make sure your Kyverno version includes this support.

## Advantages over init containers

| | Init container + emptyDir | Image volume |
|-|---------------------------|--------------|
| Extra containers | Yes (init container required) | No |
| Network access at startup | Yes (`wget` downloads the binary) | No (pre-pulled by kubelet) |
| Startup latency | Higher (download + extract) | Lower (image layer cached) |
| Reproducibility | Depends on external URL availability | Pinned to image digest/tag |
| Complexity | Higher (shell commands, volume wiring) | Lower (declarative volume spec) |
