# README
This project handles syncing certificates managed in kubernetes into AWS ACM, so that they can be used with Application Load Balancers


Basic usage:
To import a certificate to ACM automatically, annotate the Certificate resource with `legalzoom.com/import-to-acm: 'true'`. 

Permissions:
This controller requires List,Get,Watch permissions on Secrets and Certificates across any namespaces that you wish to allow certificates to be imported into ACM.

On the AWS side, it requires all ACM permissions except for acm:RequestCertificate and acm:ResendValidationEmail
