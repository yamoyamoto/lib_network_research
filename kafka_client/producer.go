package main

import (
	"analyzer/cmd"
	"analyzer/datasource"
	"analyzer/models"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"kafka/kafka"
	"log"
	"os"
	"time"
)

func main() {
	fmt.Println("started...")

	if err := runProducer(); err != nil {
		panic(err)
	}
}

var topicNameFlag = ""
var kafkaEndpointFlag = ""
var roleArnFlag = ""
var vulPackgeInputFile = ""
var ecosystemType = ""

func runProducer() error {
	flag.StringVar(&topicNameFlag, "t", "", "")
	flag.StringVar(&kafkaEndpointFlag, "k", "", "")
	flag.StringVar(&roleArnFlag, "r", "", "")
	flag.StringVar(&vulPackgeInputFile, "f", "", "")
	flag.StringVar(&ecosystemType, "e", "", "")
	flag.Parse()

	db, err := sql.Open("mysql", "root@(localhost:3306)/lib")
	if err != nil {
		return err
	}

	// 脆弱性のリスト
	file, err := os.Open(vulPackgeInputFile)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			panic(err)
		}
	}(file)

	r := csv.NewReader(file)
	rows, err := r.ReadAll()
	if err != nil {
		return err
	}

	vulPackages := make([]cmd.VulPackage, 0)
	for i := len(rows) - 1; i >= 0; i-- {
		projectId, err := datasource.GetPackageIdByName(db, models.EcosystemType(ecosystemType), rows[i][1])
		if err != nil {
			log.Printf("エラーが発生しました. error: %s", err)
			continue
		}
		vulPackages = append(vulPackages, cmd.VulPackage{
			PackageId:     projectId,
			PackageName:   rows[i][1],
			VulConstraint: rows[i][2],
			Deps:          0,
		})
	}
	allVulPackageCount := len(vulPackages)

	for len(vulPackages) != 0 {
		//affectedVulCount := 0

		//vulPakageName := vulPackages[0].PackageName
		vulPackageId := vulPackages[0].PackageId
		vulPackageDeps := vulPackages[0].Deps
		vulConstraint := vulPackages[0].VulConstraint
		vulPackages = vulPackages[1:]

		// 深さ制限
		if vulPackageDeps > 0 {
			continue
		}

		// vulPackageに依存しているパッケージを全て取得
		packages, err := datasource.FetchAffectedPackagesWithVersions(db, models.EcosystemType(ecosystemType), vulPackageId)
		if err != nil {
			return err
		}
		log.Printf("パッケージ %d/%d, 脆弱性を持ったパッケージ(%s)に依存しているパッケージが %d 個見つかりました", len(vulPackages), allVulPackageCount, vulPackageId, len(packages))

		// 脆弱性パッケージのリリース履歴を取得する
		vulPackageReleaseLogs, err := datasource.GetVulPackageVersionsById(db, vulPackageId, models.EcosystemType(ecosystemType))
		if err != nil {
			return err
		}

		// kafkaにメッセージを送る
		// TODO: メッセージサイズが大きい場合、分割してProduce
		message, err := json.Marshal(cmd.Message{
			AffectedPackageReleaseLogs: packages,
			VulPackageReleaseLogs:      vulPackageReleaseLogs,
			VulConstraint:              vulConstraint,
		})
		log.Printf("send message to kafka... message size: %d KB", len(message)/1000)
		if err != nil {
			return err
		}
		if err := kafka.ProduceMessage(message, kafkaEndpointFlag, roleArnFlag, topicNameFlag); err != nil {
			log.Println("failed to produce message to kafka.", err)
		}
		time.Sleep(3 * time.Second)
	}
	return nil
}
