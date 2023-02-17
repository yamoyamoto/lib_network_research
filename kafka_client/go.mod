module kafka

go 1.18

require (
	analyzer v0.0.0
	github.com/aws/aws-sdk-go v1.41.3
	github.com/segmentio/kafka-go v0.4.38
	github.com/segmentio/kafka-go/sasl/aws_msk_iam v0.0.0-20230127181734-172fe7593625
)

require (
	github.com/Masterminds/semver/v3 v3.2.0 // indirect
	github.com/go-sql-driver/mysql v1.7.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/klauspost/compress v1.15.9 // indirect
	github.com/pierrec/lz4/v4 v4.1.15 // indirect
)

replace analyzer v0.0.0 => ./../analyzer
