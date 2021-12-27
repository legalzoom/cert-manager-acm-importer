module github.com/legalzoom/cert-manager-acm-importer

go 1.16

require (
	github.com/aws/aws-sdk-go v1.31.3
	github.com/go-logr/logr v0.2.1-0.20200730175230-ee2de8da5be6
	github.com/jetstack/cert-manager v1.0.3
	github.com/onsi/ginkgo v1.12.1 // indirect
	github.com/onsi/gomega v1.10.1 // indirect
	go.uber.org/zap v1.10.0
	gopkg.in/yaml.v2 v2.2.8
	k8s.io/api v0.19.0
	k8s.io/apimachinery v0.19.0
	k8s.io/client-go v0.19.0
	sigs.k8s.io/controller-runtime v0.6.2
)
