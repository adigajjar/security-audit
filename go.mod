module github.com/adigajjar/security-audit

go 1.26.1

replace github.com/ShubhankarSalunke/chaos-engineering => ../chaos-engineering

require (
	github.com/ShubhankarSalunke/chaos-engineering v0.0.0-00010101000000-000000000000
	github.com/ShubhankarSalunke/lucifer/connectors v0.0.0-00010101000000-000000000000
	github.com/aws/aws-sdk-go-v2 v1.41.5
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.296.0
	github.com/aws/aws-sdk-go-v2/service/iam v1.53.6
	github.com/aws/aws-sdk-go-v2/service/s3 v1.98.0
)

require (
	github.com/aws/aws-sdk-go-v2/config v1.32.13 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.19.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.41.10 // indirect
)

require (
	github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk v1.34.1
	github.com/google/uuid v1.6.0 // indirect
	golang.org/x/crypto v0.48.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
)

require (
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.8 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.21 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.21 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.21 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.6 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.22 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.9.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.21 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.19.21 // indirect
	github.com/aws/aws-sdk-go-v2/service/lambda v1.88.3
	github.com/aws/aws-sdk-go-v2/service/rds v1.116.3
	github.com/aws/aws-sdk-go-v2/service/signin v1.0.9 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.30.14 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.35.18 // indirect
	github.com/aws/smithy-go v1.24.2 // indirect
	gopkg.in/yaml.v3 v3.0.1
)

replace github.com/ShubhankarSalunke/lucifer/connectors => ../connectors
