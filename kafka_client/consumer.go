package main

import (
	"analyzer/cmd"
	"analyzer/models"
	"analyzer/sv"
	"context"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/Masterminds/semver/v3"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"
	kafka "github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl/aws_msk_iam"
	"log"
	"os"
	"strconv"
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
	var ecosystemType = ""
	flag.StringVar(&topicNameFlag, "t", "", "")
	flag.StringVar(&kafkaEndpointFlag, "k", "", "")
	flag.StringVar(&roleArnFlag, "r", "", "")
	flag.StringVar(&ecosystemType, "e", "", "")
	flag.Parse()

	affectedPackagesOutputFile, err := os.Create("test.csv")
	if err != nil {
		return err
	}
	w := csv.NewWriter(affectedPackagesOutputFile)
	if err := w.Write([]string{
		"project_id",
		"vul_project_id",
		"vul_start_datetime",
		"vul_end_datetime",
		"vul_start_timestamp",
		"vul_end_timestamp",
		"compliantType",
		"vul_start_dependency_compliant",
		"vul_start_version",
		"vul_deps",
		// 脆弱性パッケージが(このパッケージも含めて)影響を与えたパッケージの総数
		"vul_total_count",
		"source_rank",
	}); err != nil {
		return err
	}

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

	startTime := time.Now()
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

		message := cmd.Message{}
		if err := json.Unmarshal(m.Value, &message); err != nil {
			return err
		}
		if err := handler(w, message, models.EcosystemType(ecosystemType)); err != nil {
			return err
		}
	}

	if err := r.Close(); err != nil {
		log.Fatal("failed to close reader:", err)
	}

	return nil
}

func handler(w *csv.Writer, message cmd.Message, ecosystemType models.EcosystemType) error {
	for affectedPackageId, releaseLogs := range message.AffectedPackageReleaseLogs {
		results, err := analyzeVulnerabilityDuration(affectedPackageId, message.VulPackageId, message.VulConstraint, ecosystemType, mergeTwoReleaseLogs(releaseLogs, message.VulPackageReleaseLogs))
		if err != nil {
			log.Printf("エラーが発生しました. error: %s, vulConstraint: %s", err, message.VulConstraint)
			continue
		}
		for _, r := range results {
			var endDate *time.Time
			if r.VulEndDate != nil {
				endDate = r.VulEndDate
			} else {
				t := time.Now()
				endDate = &t
			}
			if err := w.Write([]string{
				affectedPackageId,
				message.VulPackageId,
				r.VulStartDate.String(),
				endDate.String(),
				strconv.FormatInt(r.VulStartDate.Unix(), 10),
				strconv.FormatInt(endDate.Unix(), 10),
				strconv.FormatInt(int64(r.CompliantType), 10),
				r.VulStartDependencyRequirement,
				r.VulStartVersion.String(),
				"0", // deps
				strconv.FormatInt(int64(len(results)), 10),
				"0", // strconv.FormatInt(affectedPackage.SourceRank, 10),
			}); err != nil {
				return err
			}
		}
	}
	w.Flush()
	return nil
}

type AnalyzeVulnerabilityDurationResult struct {
	PackageId                     string
	VulPackageId                  string
	VulStartDate                  *time.Time
	VulEndDate                    *time.Time
	CompliantType                 models.CompliantType
	VulStartDependencyRequirement string
	VulStartVersion               *semver.Version
	VulEndVersion                 *semver.Version
}

func mergeTwoReleaseLogs(a []models.ReleaseLog, b []models.ReleaseLog) []models.ReleaseLog {
	i := 0
	j := 0
	newReleaseLogs := make([]models.ReleaseLog, len(a)+len(b))
	for k := 0; k < len(a)+len(b); k++ {
		if i < len(a) && j < len(b) && a[i].PublishedTimestamp < b[j].PublishedTimestamp {
			newReleaseLogs[k] = a[i]
			i++
		} else if j < len(b) {
			newReleaseLogs[k] = b[j]
			j++
		}
	}

	return newReleaseLogs
}

func analyzeVulnerabilityDuration(packageId string, vulPackageId string, vulConstraint string, ecosystemType models.EcosystemType, releaseLogs []models.ReleaseLog) ([]AnalyzeVulnerabilityDurationResult, error) {
	// 脆弱性の影響を受けていた期間を特定
	// 変数: 脆弱性の始まりと終わりのバージョン
	isAlreadyPublishedPackage := false
	nowAffectedVulnerability := false
	var affectedVulnerabilityStartDate *time.Time

	// 脆弱性の影響を受け始めたときの情報
	var vulStartConstraint string
	var vulStartVersion *semver.Version

	results := make([]AnalyzeVulnerabilityDurationResult, 0)
	for i, releaseLog := range releaseLogs {
		if releaseLog.PackageType == "package" {
			// 依存元のパッケージ
			isAffectedVulnerability, v, err := isAffectedVulnerabilityWithPackage(*releaseLog.DependencyRequirements, releaseLogs[0:i], vulConstraint)
			if err != nil {
				return nil, err
			}
			if isAffectedVulnerability {
				if !nowAffectedVulnerability {
					d, err := time.Parse("2006-01-02 15:04:05", releaseLog.PublishedTimestamp)
					if err != nil {
						return nil, err
					}
					affectedVulnerabilityStartDate = &d
					nowAffectedVulnerability = true

					vulStartConstraint = *releaseLog.DependencyRequirements
					vulStartVersion = v

					//fmt.Printf("脆弱性の影響を受けはじめた. 受けはじめの時刻: %s\n", affectedVulnerabilityStartDate.String())
				}
				// 継続して脆弱性の影響を受けている
			} else {
				if nowAffectedVulnerability {
					affectedVulnerabilityEndDate, err := time.Parse("2006-01-02 15:04:05", releaseLogs[i].PublishedTimestamp)
					if err != nil {
						return nil, err
					}
					//fmt.Printf("脆弱性の影響を受け終わった. 受け終わりの時刻: %s\n", affectedVulnerabilityEndDate.String())

					compliantType, err := sv.CheckCompliantSemVer(vulStartConstraint, vulStartVersion)
					if err != nil {
						return nil, err
					}

					// 脆弱性が存在していた最新バージョンを取得したいので、自分のリリースを入れる必要はない
					vulEndVersion, err := findLatestPackageVersion(releaseLogs[0:i])
					if err != nil {
						return nil, err
					}

					results = append(results, AnalyzeVulnerabilityDurationResult{
						PackageId:                     packageId,
						VulPackageId:                  vulPackageId,
						VulStartDate:                  affectedVulnerabilityStartDate,
						VulEndDate:                    &affectedVulnerabilityEndDate,
						CompliantType:                 compliantType,
						VulStartDependencyRequirement: vulStartConstraint,
						VulStartVersion:               vulStartVersion,
						VulEndVersion:                 vulEndVersion,
					})

					// 状態を初期化
					nowAffectedVulnerability = false
					affectedVulnerabilityStartDate = nil
					vulStartConstraint = ""
					vulStartVersion = nil
				}
			}
			isAlreadyPublishedPackage = true
		} else if releaseLog.PackageType == "vul_package" {
			// 依存先のパッケージ(脆弱性を発生させたパッケージ)
			// beforeReleaseには自分のリリースも入れる必要がある
			isAffectedVulnerability, v, err := isAffectedVulnerabilityWithVulPackage(isAlreadyPublishedPackage, releaseLogs[0:i+1], vulConstraint)
			if err != nil {
				return nil, err
			}
			if isAffectedVulnerability {
				if !nowAffectedVulnerability {
					d, err := time.Parse("2006-01-02 15:04:05", releaseLog.PublishedTimestamp)
					if err != nil {
						return nil, err
					}
					affectedVulnerabilityStartDate = &d
					nowAffectedVulnerability = true
					vulStartVersion = v

					//fmt.Printf("脆弱性の影響を受けはじめた. 受けはじめの時刻: %s\n", affectedVulnerabilityStartDate.String())
				}
				// 継続して脆弱性の影響を受けている
			} else {
				if nowAffectedVulnerability {
					affectedVulnerabilityEndDate, err := time.Parse("2006-01-02 15:04:05", releaseLogs[i].PublishedTimestamp)
					if err != nil {
						return nil, err
					}
					//fmt.Printf("脆弱性の影響を受け終わった!! 受け終わりの時刻: %s\n", affectedVulnerabilityEndDate.String())

					compliantType, err := sv.CheckCompliantSemVer(vulStartConstraint, vulStartVersion)
					if err != nil {
						return nil, err
					}

					// 脆弱性が存在していた最新バージョンを取得したいので、自分のリリースを入れる必要はない
					vulEndVersion, err := findLatestPackageVersion(releaseLogs[0:i])
					if err != nil {
						return nil, err
					}

					results = append(results, AnalyzeVulnerabilityDurationResult{
						PackageId:                     packageId,
						VulPackageId:                  vulPackageId,
						VulStartDate:                  affectedVulnerabilityStartDate,
						VulEndDate:                    &affectedVulnerabilityEndDate,
						CompliantType:                 compliantType,
						VulStartDependencyRequirement: vulStartConstraint,
						VulStartVersion:               vulStartVersion,
						VulEndVersion:                 vulEndVersion,
					})

					// 状態を初期化
					nowAffectedVulnerability = false
					affectedVulnerabilityStartDate = nil
					vulStartConstraint = ""
					vulStartVersion = nil
				}
			}
		} else {
			return nil, fmt.Errorf("got unknown type of package. type: %s", releaseLog.PackageType)
		}
	}

	if nowAffectedVulnerability {
		// 脆弱性が存在していた最新バージョンを取得したいので、自分のリリースを入れる必要はない
		vulEndVersion, err := findLatestPackageVersion(releaseLogs)
		if err != nil {
			return nil, err
		}

		compliantType, err := sv.CheckCompliantSemVer(vulStartConstraint, vulStartVersion)
		if err != nil {
			return nil, err
		}

		results = append(results, AnalyzeVulnerabilityDurationResult{
			PackageId:                     packageId,
			VulPackageId:                  vulPackageId,
			VulStartDate:                  affectedVulnerabilityStartDate,
			VulEndDate:                    nil,
			CompliantType:                 compliantType,
			VulStartDependencyRequirement: vulStartConstraint,
			VulStartVersion:               vulStartVersion,
			VulEndVersion:                 vulEndVersion,
		})
	}

	return results, nil
}

func findLatestPackageVersion(beforeReleases []models.ReleaseLog) (*semver.Version, error) {
	for i := len(beforeReleases) - 1; i >= 0; i-- {
		if beforeReleases[i].PackageType == "package" {
			v, err := semver.NewVersion(beforeReleases[i].VersionNumber)
			if err != nil {
				return nil, err
			}
			return v, nil
		}
	}
	return nil, fmt.Errorf("最新の依存関係制約が見つかりませんでした")
}

func findLatestPackageDependencyRequirements(beforeReleases []models.ReleaseLog) (string, error) {
	for i := len(beforeReleases) - 1; i >= 0; i-- {
		if beforeReleases[i].PackageType == "package" {
			return *beforeReleases[i].DependencyRequirements, nil
		}
	}
	return "", fmt.Errorf("最新の依存関係制約が見つかりませんでした")
}

func isAffectedVulnerabilityWithVulPackage(isAlreadyPublishedPackage bool, beforeReleases []models.ReleaseLog, vulConstraint string) (bool, *semver.Version, error) {
	if !isAlreadyPublishedPackage {
		return false, nil, nil
	}

	requirements, err := findLatestPackageDependencyRequirements(beforeReleases)
	if err != nil {
		return false, nil, err
	}

	for i := len(beforeReleases) - 1; i >= 0; i-- {
		if beforeReleases[i].PackageType != "vul_package" {
			continue
		}

		v, err := semver.NewVersion(beforeReleases[i].VersionNumber)
		if err != nil {
			return false, nil, err
		}

		// 制約を満たすかどうか
		c, err := semver.NewConstraint(requirements)
		if err != nil {
			return false, nil, err
		}
		isValidVersionWithRequirements := c.Check(v)
		// 制約を満たしていなければ脆弱かどうかを調べる必要がないのでcontinue
		if !isValidVersionWithRequirements {
			continue
		}

		// 脆弱性影響を受けているかどうか
		c, err = semver.NewConstraint(vulConstraint)
		if err != nil {
			return false, nil, err
		}
		version, err := semver.NewVersion(beforeReleases[i].VersionNumber)
		if err != nil {
			return false, nil, err
		}

		return c.Check(v), version, nil
	}
	return false, nil, fmt.Errorf("制約を満たすバージョンが見つかりませんでした. 制約: '%s'", requirements)
}

func isAffectedVulnerabilityWithPackage(requirements string, beforeReleases []models.ReleaseLog, vulConstraint string) (bool, *semver.Version, error) {
	for i := len(beforeReleases) - 1; i >= 0; i-- {
		// 最新から順に制約を満たすかどうか確認する
		if beforeReleases[i].PackageType == "vul_package" {
			v, err := semver.NewVersion(beforeReleases[i].VersionNumber)
			if err != nil {
				return false, nil, err
			}

			// 制約を満たすかどうか
			c, err := semver.NewConstraint(requirements)
			if err != nil {
				return false, nil, err
			}
			isValidVersionWithRequirements := c.Check(v)
			// 制約を満たしていなければ脆弱かどうかを調べる必要がないのでcontinue
			if !isValidVersionWithRequirements {
				continue
			}

			// 脆弱性影響を受けているかどうか
			c, err = semver.NewConstraint(vulConstraint)
			if err != nil {
				return false, nil, err
			}

			vulStartVersion, err := semver.NewVersion(beforeReleases[i].VersionNumber)
			if err != nil {
				return false, nil, err
			}
			return c.Check(v), vulStartVersion, nil
		}
	}
	// 一度もヒットしなければ、エラー
	return false, nil, fmt.Errorf("制約を満たすバージョンが見つかりませんでした. 制約: '%s'", requirements)
}
