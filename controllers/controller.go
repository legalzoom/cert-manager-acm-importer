package controllers

import (
	"bufio"
	"bytes"
	"context"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/acm"
	aws2 "github.com/backjo/aws-cert-importer/pkg/aws"
	"github.com/go-logr/logr"
	cmapiv1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmetav1 "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"go.uber.org/zap"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"strconv"
	"strings"
)

type AcmCertificate struct {
	Summary *acm.CertificateSummary
	Tags    []*acm.Tag
}

// CertificateReconciler reconciles a CronJob object
type CertificateReconciler struct {
	client.Client
	Log        logr.Logger
	Scheme     *runtime.Scheme
	Cache      map[string]*AcmCertificate
	AcmService aws2.IAcmService
}

// +kubebuilder:rbac:groups=cert-manager.io,resources=certificate,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get

var (
	certIdAnnotation       = "legalzoom.com/cert-importer/cert-id"
	certRevisionAnnotation = "legalzoom.com/cert-importer/cert-revision"
	finalizer              = "certificate.legalzoom.com"
)

func (r *CertificateReconciler) InitializeCache() {
	sess := session.Must(session.NewSession())
	acmClient := acm.New(sess)

	r.AcmService = &aws2.AcmService{Client: acmClient}

	certs, err := acmClient.ListCertificates(&acm.ListCertificatesInput{})
	if err == nil {
		for _, cert := range certs.CertificateSummaryList {
			output, _ := acmClient.ListTagsForCertificate(&acm.ListTagsForCertificateInput{CertificateArn: cert.CertificateArn})
			for _, tag := range output.Tags {
				if *tag.Key == certIdAnnotation {
					r.Cache[*tag.Value] = &AcmCertificate{
						Summary: cert,
						Tags:    output.Tags,
					}
				}
			}
		}
	} else {
		zap.S().Error("error received", err)
	}
}

type Certificate struct {
	privateKey           []byte
	certificate          []byte
	certificateAuthority []byte
}

func (r *CertificateReconciler) GetCertificateSecret(certificate cmapiv1.Certificate) *Certificate {
	var secret = &v1.Secret{}
	ctx := context.Background()
	_ = r.Get(ctx, types.NamespacedName{
		Namespace: certificate.Namespace,
		Name:      certificate.Spec.SecretName,
	}, secret)
	tlsKey := secret.Data["tls.key"]
	tlsCrt := secret.Data["tls.crt"]

	scanner := bufio.NewScanner(strings.NewReader(string(tlsCrt)))

	var certBuffer bytes.Buffer
	var caBuffer bytes.Buffer
	doneReadingCert := false
	for scanner.Scan() {
		line := scanner.Text()
		if doneReadingCert {
			caBuffer.WriteString(line)
			caBuffer.WriteString("\n")
		} else if line == "-----END CERTIFICATE-----" {
			certBuffer.WriteString(line)
			doneReadingCert = true
		} else {
			certBuffer.WriteString(line)
			certBuffer.WriteString("\n")
		}
	}

	return &Certificate{
		privateKey:           tlsKey,
		certificate:          certBuffer.Bytes(),
		certificateAuthority: caBuffer.Bytes(),
	}
}

func (r *CertificateReconciler) GetImportCertificateInput(certificate cmapiv1.Certificate, summary *acm.CertificateSummary, existingTags []*acm.Tag) acm.ImportCertificateInput {
	var certRevision int
	var certificateArn *string

	if certificate.Status.Revision != nil {
		certRevision = *certificate.Status.Revision
	}

	certificateData := r.GetCertificateSecret(certificate)
	tags := []*acm.Tag{}

	tags = append(tags, &acm.Tag{
		Key:   aws.String(certRevisionAnnotation),
		Value: aws.String(strconv.Itoa(certRevision)),
	})

	tags = append(tags, &acm.Tag{
		Key: aws.String(certIdAnnotation),
		Value: aws.String(types.NamespacedName{
			Namespace: certificate.Namespace,
			Name:      certificate.Name,
		}.String()),
	})

	if summary != nil {
		certificateArn = summary.CertificateArn
		for _, tag := range existingTags {
			if *tag.Key != certRevisionAnnotation && *tag.Key != certIdAnnotation {
				tags = append(tags, tag)
			}
		}
	}

	return acm.ImportCertificateInput{
		Certificate:      certificateData.certificate,
		CertificateArn:   certificateArn,
		CertificateChain: certificateData.certificateAuthority,
		PrivateKey:       certificateData.privateKey,
		Tags:             tags,
	}
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func removeString(slice []string, s string) (result []string) {
	for _, item := range slice {
		if item == s {
			continue
		}
		result = append(result, item)
	}
	return
}

func (r *CertificateReconciler) CertificateNeedsUpdated(req ctrl.Request, certificate *cmapiv1.Certificate) bool {
	existingCert := r.Cache[req.NamespacedName.String()]
	if existingCert != nil && certificate.Status.Revision != nil {
		resolvedAcmTags := existingCert.Tags

		for _, tag := range resolvedAcmTags {
			if *tag.Key == certRevisionAnnotation {
				awsRevision, _ := strconv.Atoi(*tag.Value)
				return awsRevision < *certificate.Status.Revision
			}
		}
		return true
	} else {
		for _, condition := range certificate.Status.Conditions {
			if condition.Type == cmapiv1.CertificateConditionReady {
				if condition.Status == cmmetav1.ConditionTrue {
					return true
				} else {
					return false
				}
			}
		}
		return false
	}
}

func (r *CertificateReconciler) CertificateIsManaged(certificate *cmapiv1.Certificate) bool {
	importToAcm := certificate.Annotations["legalzoom.com/import-to-acm"]
	return importToAcm == "true"
}

func (r *CertificateReconciler) AddFinalizerIfNeeded(certificate *cmapiv1.Certificate) bool {
	foundFinalizer := false
	for _, certFinalizer := range certificate.Finalizers {
		if certFinalizer == finalizer {
			foundFinalizer = true
		}
	}

	if !foundFinalizer {
		certificate.Finalizers = append(certificate.Finalizers, finalizer)
		return true
	}
	return false
}

func (r *CertificateReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()

	var certificate cmapiv1.Certificate
	if err := r.Get(ctx, req.NamespacedName, &certificate); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	var resolvedAcmCertificate *acm.CertificateSummary
	var resolvedAcmTags []*acm.Tag
	if r.CertificateIsManaged(&certificate) {
		zap.S().Info("Reconciling ", req.NamespacedName.String())

		if !certificate.ObjectMeta.DeletionTimestamp.IsZero() {
			if contains(certificate.ObjectMeta.Finalizers, finalizer) {
				zap.S().Info("Attempting to delete in ACM ", req.NamespacedName.String())
				_, err := r.AcmService.DeleteCertificate(&acm.DeleteCertificateInput{
					CertificateArn: r.Cache[req.NamespacedName.String()].Summary.CertificateArn,
				})

				if err == nil {
					r.Cache[req.NamespacedName.String()] = nil
				} else {
					if _, ok := err.(*acm.ResourceNotFoundException); ok {
						err = nil
						zap.S().Errorw("Failed to delete certificate in ACM. Not found. Removing finalizer.",
							zap.Error(err),
							zap.String("certificate", req.NamespacedName.String()),
							zap.String("arn", *r.Cache[req.NamespacedName.String()].Summary.CertificateArn),
						)
					} else {
						zap.S().Errorw("Failed to delete certificate in ACM",
							zap.Error(err),
							zap.String("certificate", req.NamespacedName.String()),
							zap.String("arn", *r.Cache[req.NamespacedName.String()].Summary.CertificateArn),
						)
						return ctrl.Result{}, err
					}
				}

				certificate.ObjectMeta.Finalizers = removeString(certificate.ObjectMeta.Finalizers, finalizer)
				if err := r.Update(context.Background(), &certificate); err != nil {
					return reconcile.Result{}, err
				}

				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}

		if r.CertificateNeedsUpdated(req, &certificate) {
			existingCert := r.Cache[req.NamespacedName.String()]
			if existingCert != nil {
				resolvedAcmCertificate = existingCert.Summary
				resolvedAcmTags = existingCert.Tags
			}

			var importCertificateInput = r.GetImportCertificateInput(certificate, resolvedAcmCertificate, resolvedAcmTags)
			result, err := r.AcmService.UpsertCertificate(&importCertificateInput)

			if err != nil {
				return ctrl.Result{}, err
			}
			r.Cache[req.NamespacedName.String()] = &AcmCertificate{
				Summary: &acm.CertificateSummary{
					CertificateArn: result.CertificateArn,
				},
				Tags: result.Tags,
			}
		}

		if r.AddFinalizerIfNeeded(&certificate) {
			if err := r.Update(context.Background(), &certificate); err != nil {
				return reconcile.Result{}, err
			}
		}
	}

	return ctrl.Result{}, nil
}

func (r *CertificateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.InitializeCache()
	return ctrl.NewControllerManagedBy(mgr).
		For(&cmapiv1.Certificate{}).
		Complete(r)
}
