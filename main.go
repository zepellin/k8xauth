package main

import (
	"k8xauth/cmd"
	_ "k8xauth/cmd/aks"
	_ "k8xauth/cmd/eks"
	_ "k8xauth/cmd/genericoidc"
	_ "k8xauth/cmd/gke"
)

func main() {
	cmd.Execute()
}
