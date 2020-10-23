package controllers

import (
	"bufio"
	"bytes"
	"context"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/acm"
	"go.uber.org/zap"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"strconv"
	"strings"

	"github.com/go-logr/logr"
	cmapiv1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type AcmCertificate struct {
	summary *acm.CertificateSummary
	tags    []*acm.Tag
}

// CertificateReconciler reconciles a CronJob object
type CertificateReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
	Cache  map[string]*AcmCertificate
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
	certs, err := acmClient.ListCertificates(&acm.ListCertificatesInput{})
	if err == nil {
		for _, cert := range certs.CertificateSummaryList {
			output, _ := acmClient.ListTagsForCertificate(&acm.ListTagsForCertificateInput{CertificateArn: cert.CertificateArn})
			for _, tag := range output.Tags {
				if *tag.Key == certIdAnnotation {
					r.Cache[*tag.Value] = &AcmCertificate{
						summary: cert,
						tags:    output.Tags,
					}
				}
			}
		}
	} else {
		zap.S().Error("error received", err)
	}
}

func (r *CertificateReconciler) GetImportCertificateInput(certificate cmapiv1.Certificate, summary *acm.CertificateSummary, tags []*acm.Tag) acm.ImportCertificateInput {
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
	if summary != nil {
		for _, tag := range tags {
			if *tag.Key == certRevisionAnnotation {
				*tag.Value = strconv.Itoa(*certificate.Status.Revision)
			}
		}

		return acm.ImportCertificateInput{
			Certificate:      certBuffer.Bytes(),
			CertificateArn:   summary.CertificateArn,
			CertificateChain: caBuffer.Bytes(),
			PrivateKey:       tlsKey,
			Tags:             tags,
		}
	} else {
		newTags := []*acm.Tag{
			{
				Key:   aws.String(certRevisionAnnotation),
				Value: aws.String(strconv.Itoa(*certificate.Status.Revision)),
			},
			{
				Key: aws.String(certIdAnnotation),
				Value: aws.String(types.NamespacedName{
					Namespace: certificate.Namespace,
					Name:      certificate.Name,
				}.String()),
			},
		}

		return acm.ImportCertificateInput{
			Certificate:      certBuffer.Bytes(),
			CertificateChain: caBuffer.Bytes(),
			PrivateKey:       tlsKey,
			Tags:             newTags,
		}
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

func (r *CertificateReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	sess := session.Must(session.NewSession())
	ctx := context.Background()
	acmClient := acm.New(sess)

	var certificate cmapiv1.Certificate
	if err := r.Get(ctx, req.NamespacedName, &certificate); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	importToAcm := certificate.Annotations["legalzoom.com/import-to-acm"]
	var resolvedAcmCertificate *acm.CertificateSummary
	var resolvedAcmTags []*acm.Tag

	if !certificate.ObjectMeta.DeletionTimestamp.IsZero() {
		//handle delete
		if contains(certificate.ObjectMeta.Finalizers, finalizer) {
			zap.S().Info("Attempting to delete in ACM ", req.NamespacedName.String())
			_, err := acmClient.DeleteCertificate(&acm.DeleteCertificateInput{
				CertificateArn: r.Cache[req.NamespacedName.String()].summary.CertificateArn,
			})

			if err == nil {
				r.Cache[req.NamespacedName.String()] = nil
			} else {
				zap.S().Errorw("Failed to delete certificate in ACM",
					zap.Error(err),
					zap.String("certificate", req.NamespacedName.String()),
					zap.String("arn", *r.Cache[req.NamespacedName.String()].summary.CertificateArn),
				)
				return ctrl.Result{}, err
			}

			certificate.ObjectMeta.Finalizers = removeString(certificate.ObjectMeta.Finalizers, finalizer)
			if err := r.Update(context.Background(), &certificate); err != nil {
				return reconcile.Result{}, err
			}

			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	if importToAcm == "true" {
		zap.S().Info("Reconciling ", req.NamespacedName.String())
		existingCert := r.Cache[req.NamespacedName.String()]
		if existingCert != nil {
			resolvedAcmCertificate = existingCert.summary
			resolvedAcmTags = existingCert.tags
		}

		if resolvedAcmCertificate != nil && certificate.Status.Revision != nil {
			var revision int
			for _, tag := range resolvedAcmTags {
				if *tag.Key == certRevisionAnnotation {
					revision, _ = strconv.Atoi(*tag.Value)
				}
			}
			if revision < *certificate.Status.Revision {
				zap.S().Info(req.NamespacedName.String(), "Revision in Certificate Resource is newer than in ACM. Attempting to re-import")
				var importCertificateInput = r.GetImportCertificateInput(certificate, resolvedAcmCertificate, resolvedAcmTags)
				tags := importCertificateInput.Tags
				importCertificateInput.Tags = nil
				result, err := acmClient.ImportCertificate(&importCertificateInput)
				if err != nil {
					zap.S().Errorw("Failed to re-import certificate in ACM", zap.Error(err), zap.String("certificate", req.NamespacedName.String()))
				} else {
					zap.S().Infow("Reimported into ACM",
						zap.String("arn", *result.CertificateArn),
						zap.String("certificate", req.NamespacedName.String()),
					)
					_, err = acmClient.AddTagsToCertificate(&acm.AddTagsToCertificateInput{
						CertificateArn: importCertificateInput.CertificateArn,
						Tags:           tags,
					})
					if err != nil {
						r.Cache[req.NamespacedName.String()].tags = tags
						return ctrl.Result{}, err
					}
				}
				return ctrl.Result{}, nil
			}
		} else if certificate.Status.Revision != nil {
			var importCertificateInput = r.GetImportCertificateInput(certificate, nil, nil)
			result, err := acmClient.ImportCertificate(&importCertificateInput)
			if err != nil {
				zap.S().Errorw("Error importing new certificate", zap.Error(err))
				return ctrl.Result{}, err
			} else if result != nil {
				zap.S().Infow("Imported new certificate into ACM",
					zap.String("arn", *result.CertificateArn),
					zap.String("certificate", req.NamespacedName.String()),
				)
				_ = r.Get(ctx, req.NamespacedName, &certificate)
				certificate.ObjectMeta.Finalizers = append(certificate.ObjectMeta.Finalizers, finalizer)
				err = r.Update(context.Background(), &certificate)
				if err != nil {
					zap.S().Error(err)
				}
				r.Cache[req.NamespacedName.String()] = &AcmCertificate{
					summary: &acm.CertificateSummary{
						CertificateArn: result.CertificateArn,
					},
					tags: importCertificateInput.Tags,
				}
				return ctrl.Result{}, nil
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
