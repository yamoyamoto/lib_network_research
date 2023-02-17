package kafka

import (
	"context"
	"crypto/tls"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"
	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl/aws_msk_iam"
	"strings"
	"time"
)

func ProduceMessage(message []byte, endpoint string, roleArn string, topicName string) error {
	mechanism := &aws_msk_iam.Mechanism{
		Signer: v4.NewSigner(
			stscreds.NewCredentials(session.Must(session.NewSession()), roleArn),
		),
		Region:   "ap-northeast-1",
		SignTime: time.Now(),
	}

	sharedTransport := &kafka.Transport{
		SASL: mechanism,
		TLS:  &tls.Config{},
	}
	w := kafka.Writer{
		Addr:         kafka.TCP(strings.Split(endpoint, ",")...),
		Balancer:     &kafka.Hash{},
		Transport:    sharedTransport,
		WriteTimeout: 5 * time.Second,
	}

	if err := w.WriteMessages(context.Background(), kafka.Message{
		Topic: topicName,
		Key:   []byte("Key-A"),
		Value: message,
	}); err != nil {
		return err
	}

	return nil
}
