package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"
	kafka "github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl/aws_msk_iam"
	"log"
	"strings"
	"time"
)

func main() {
	fmt.Println("started...")

	if err := runKafkaApp(); err != nil {
		panic(err)
	}
}

func runKafkaApp() error {
	var topicNameFlag = ""
	var kafkaEndpointFlag = ""
	var roleArnFlag = ""
	flag.StringVar(&topicNameFlag, "t", "", "")
	flag.StringVar(&kafkaEndpointFlag, "k", "", "")
	flag.StringVar(&roleArnFlag, "r", "", "")
	flag.Parse()

	var mechanism = &aws_msk_iam.Mechanism{
		Signer: v4.NewSigner(
			stscreds.NewCredentials(session.Must(session.NewSession()), roleArnFlag),
		),
		Region: "ap-northeast-1",
	}
	dialer := &kafka.Dialer{
		Timeout:       10 * time.Second,
		DualStack:     true,
		SASLMechanism: mechanism,
		TLS:           &tls.Config{},
	}

	startTime := time.Now().Add(-time.Hour)
	batchSize := int(10e6) // 10MB

	r := kafka.NewReader(kafka.ReaderConfig{
		Brokers:   strings.Split(kafkaEndpointFlag, ","),
		Topic:     topicNameFlag,
		Partition: 0,
		MinBytes:  batchSize,
		MaxBytes:  batchSize,
		Dialer:    dialer,
	})

	r.SetOffsetAt(context.Background(), startTime) // fetch 10KB min, 1MB max
	for {
		m, err := r.ReadMessage(context.Background())

		if err != nil {
			fmt.Println("some error happened.", err)
			break
		}
		// TODO: process message
		fmt.Printf("message at offset %d: %s = %s\n", m.Offset, string(m.Key), string(m.Value))
	}

	if err := r.Close(); err != nil {
		log.Fatal("failed to close reader:", err)
	}

	return nil
}
