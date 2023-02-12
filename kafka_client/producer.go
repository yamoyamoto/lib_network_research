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
	"strings"
	"time"
)

func main() {
	fmt.Println("started...")

	if err := produceMessage(); err != nil {
		panic(err)
	}
}

func produceMessage() error {
	var topicNameFlag = ""
	var kafkaEndpointFlag = ""
	var roleArnFlag = ""
	flag.StringVar(&topicNameFlag, "t", "", "")
	flag.StringVar(&kafkaEndpointFlag, "k", "", "")
	flag.StringVar(&roleArnFlag, "r", "", "")
	flag.Parse()

	mechanism := &aws_msk_iam.Mechanism{
		Signer: v4.NewSigner(
			stscreds.NewCredentials(session.Must(session.NewSession()), roleArnFlag),
		),
		Region:   "ap-northeast-1",
		SignTime: time.Now(),
	}

	sharedTransport := &kafka.Transport{
		SASL: mechanism,
		TLS:  &tls.Config{},
	}
	w := kafka.Writer{
		Addr:         kafka.TCP(strings.Split(kafkaEndpointFlag, ",")...),
		Balancer:     &kafka.Hash{},
		Transport:    sharedTransport,
		WriteTimeout: 5 * time.Second,
	}

	if err := w.WriteMessages(context.Background(), kafka.Message{
		Topic: topicNameFlag,
		Key:   []byte("Key-A"),
		Value: []byte("Hello World!"),
	}); err != nil {
		return err
	}

	return nil
}
