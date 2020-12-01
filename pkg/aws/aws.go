package aws

import (
	"github.com/aws/aws-sdk-go/service/acm"
)

type IAcmService interface {
	UpsertCertificate(input *acm.ImportCertificateInput) (*UpsertCertificateResponse, error)
	DeleteCertificate(input *acm.DeleteCertificateInput) (*acm.DeleteCertificateOutput, error)
}

type AcmService struct {
	Client *acm.ACM
}

type UpsertCertificateResponse struct {
	CertificateArn *string
	Tags           []*acm.Tag
}

func (s *AcmService) UpsertCertificate(input *acm.ImportCertificateInput) (*UpsertCertificateResponse, error) {
	tags := input.Tags
	input.Tags = nil

	response, err := s.Client.ImportCertificate(input)
	if err != nil {
		return nil, err
	}
	_, err = s.Client.AddTagsToCertificate(&acm.AddTagsToCertificateInput{
		CertificateArn: response.CertificateArn,
		Tags:           tags,
	})

	if err != nil {
		return nil, err
	}

	return &UpsertCertificateResponse{
		CertificateArn: response.CertificateArn,
		Tags:           tags,
	}, nil
}

func (s *AcmService) DeleteCertificate(input *acm.DeleteCertificateInput) (*acm.DeleteCertificateOutput, error) {
	return s.Client.DeleteCertificate(input)
}
