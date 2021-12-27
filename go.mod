module github.com/backjo/aws-cert-importer

go 1.13

require (
	github.com/aws/aws-sdk-go v1.31.3
	github.com/go-logr/logr v0.2.1-0.20200730175230-ee2de8da5be6
	github.com/jetstack/cert-manager v1.0.3
	go.uber.org/zap v1.10.0
	k8s.io/api v0.19.0
	k8s.io/apimachinery v0.19.0
	k8s.io/client-go v0.19.0
	sigs.k8s.io/controller-runtime v0.6.2
)
