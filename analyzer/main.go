package main

import (
	"analyzer/datasource"
	"analyzer/models"
	"database/sql"
	"encoding/csv"
	"fmt"
	"github.com/Masterminds/semver"
	_ "github.com/go-sql-driver/mysql"
	"log"
	"os"
	"strconv"
	"time"
)

func main() {
	if err := handler(); err != nil {
		log.Fatal(err)
	}
}

const (
	vulConstraint = "0.1.2 - 0.3.0"
	vulPackageId  = "31296"
)

func handler() error {
	db, err := sql.Open("mysql", "root@(localhost:3306)/lib")
	if err != nil {
		return err
	}

	// vulPackageに依存しているパッケージを全て取得
	packages, err := datasource.FetchAffectedPackagesFromVulPackage(db, vulPackageId)
	if err != nil {
		return err
	}
	log.Printf("脆弱性を持ったパッケージ(%s)に依存しているパッケージが %d 個見つかりました", vulPackageId, len(packages))

	outputFile, err := os.Create("test.csv") // 書き込む先のファイル
	if err != nil {
		fmt.Println(err)
	}
	w := csv.NewWriter(outputFile)
	if err := w.Write([]string{
		"project_id",
		"vul_project_id",
		"vul_start_datetime",
		"vul_end_datetime",
		"vul_start_timestamp",
		"vul_end_timestamp",
	}); err != nil {
		return err
	}

	for _, p := range packages {
		log.Printf("↓package %s の解析結果↓", p.ProjectId)
		results, err := analyzeVulnerabilityDuration(db, p.ProjectId, "31296")
		if err != nil {
			return err
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
				p.ProjectId,
				vulPackageId,
				r.VulStartDate.String(),
				endDate.String(),
				strconv.FormatInt(r.VulStartDate.Unix(), 10),
				strconv.FormatInt(endDate.Unix(), 10),
			}); err != nil {
				return err
			}
			fmt.Printf("package %s: %s〜%s", p.ProjectId, r.VulStartDate.String(), endDate)
		}
		print("\n\n")
	}
	w.Flush()

	return nil
}

type AnalyzeVulnerabilityDurationResult struct {
	PackageId    string
	VulPackageId string
	VulStartDate *time.Time
	VulEndDate   *time.Time
}

func analyzeVulnerabilityDuration(db *sql.DB, packageId string, vulPackageId string) ([]AnalyzeVulnerabilityDurationResult, error) {
	releaseLogs, err := datasource.FetchMergedTwoPackageReleasesWithSort(db, packageId, vulPackageId)
	if err != nil {
		return nil, err
	}

	// 脆弱性の影響を受けていた期間を特定
	// 変数: 脆弱性の始まりと終わりのバージョン
	isAlreadyPublishedPackage := false
	nowAffectedVulnerability := false
	var affectedVulnerabilityStartDate *time.Time

	results := make([]AnalyzeVulnerabilityDurationResult, 0)
	for i, releaseLog := range releaseLogs {
		if releaseLog.PackageType == "package" {
			// 依存元のパッケージ
			isAffectedVulnerability, err := isAffectedVulnerabilityWithPackage(*releaseLog.DependencyRequirements, releaseLogs[0:i])
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

					results = append(results, AnalyzeVulnerabilityDurationResult{
						PackageId:    packageId,
						VulPackageId: vulPackageId,
						VulStartDate: affectedVulnerabilityStartDate,
						VulEndDate:   &affectedVulnerabilityEndDate,
					})

					// 状態を初期化
					nowAffectedVulnerability = false
					affectedVulnerabilityStartDate = nil
				}
			}
			isAlreadyPublishedPackage = true
		} else if releaseLog.PackageType == "vul_package" {
			// 依存先のパッケージ(脆弱性を発生させたパッケージ)
			// beforeReleaseには自分のリリースも入れる必要がある
			isAffectedVulnerability, err := isAffectedVulnerabilityWithVulPackage(isAlreadyPublishedPackage, releaseLogs[0:i+1])
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
					results = append(results, AnalyzeVulnerabilityDurationResult{
						PackageId:    packageId,
						VulPackageId: vulPackageId,
						VulStartDate: affectedVulnerabilityStartDate,
						VulEndDate:   &affectedVulnerabilityEndDate,
					})

					// 状態を初期化
					nowAffectedVulnerability = false
					affectedVulnerabilityStartDate = nil
				}
			}
		} else {
			return nil, fmt.Errorf("got unknown type of package. type: %s", releaseLog.PackageType)
		}
	}

	if nowAffectedVulnerability {
		results = append(results, AnalyzeVulnerabilityDurationResult{
			PackageId:    packageId,
			VulPackageId: vulPackageId,
			VulStartDate: affectedVulnerabilityStartDate,
			VulEndDate:   nil,
		})
	}

	return results, nil
}

func findLatestPackageDependencyRequirements(beforeReleases []models.ReleaseLog) (string, error) {
	for i := len(beforeReleases) - 1; i >= 0; i-- {
		if beforeReleases[i].PackageType == "package" {
			return *beforeReleases[i].DependencyRequirements, nil
		}
	}
	return "", fmt.Errorf("最新の依存関係制約が見つかりませんでした")
}

func isAffectedVulnerabilityWithVulPackage(isAlreadyPublishedPackage bool, beforeReleases []models.ReleaseLog) (bool, error) {
	if !isAlreadyPublishedPackage {
		return false, nil
	}

	requirements, err := findLatestPackageDependencyRequirements(beforeReleases)
	if err != nil {
		return false, err
	}

	for i := len(beforeReleases) - 1; i >= 0; i-- {
		if beforeReleases[i].PackageType != "vul_package" {
			continue
		}

		v, err := semver.NewVersion(beforeReleases[i].VersionNumber)
		if err != nil {
			return false, err
		}

		// 制約を満たすかどうか
		c, err := semver.NewConstraint(requirements)
		if err != nil {
			return false, err
		}
		isValidVersionWithRequirements := c.Check(v)
		// 制約を満たしていなければ脆弱かどうかを調べる必要がないのでcontinue
		if !isValidVersionWithRequirements {
			continue
		}

		// 脆弱性影響を受けているかどうか
		c, err = semver.NewConstraint(vulConstraint)
		if err != nil {
			return false, err
		}
		isAffectedVulnerability := c.Check(v)

		return isAffectedVulnerability, nil
	}
	return false, fmt.Errorf("制約を満たすバージョンが見つかりませんでした. 制約: '%s'", requirements)
}

func isAffectedVulnerabilityWithPackage(requirements string, beforeReleases []models.ReleaseLog) (bool, error) {
	for i := len(beforeReleases) - 1; i >= 0; i-- {
		// 最新から順に制約を満たすかどうか確認する
		if beforeReleases[i].PackageType == "vul_package" {
			v, err := semver.NewVersion(beforeReleases[i].VersionNumber)
			if err != nil {
				return false, err
			}

			// 制約を満たすかどうか
			c, err := semver.NewConstraint(requirements)
			if err != nil {
				return false, err
			}
			isValidVersionWithRequirements := c.Check(v)
			// 制約を満たしていなければ脆弱かどうかを調べる必要がないのでcontinue
			if !isValidVersionWithRequirements {
				continue
			}

			// 脆弱性影響を受けているかどうか
			c, err = semver.NewConstraint(vulConstraint)
			if err != nil {
				return false, err
			}
			isAffectedVulnerability := c.Check(v)

			return isAffectedVulnerability, nil
		}
	}
	// 一度もヒットしなければ、エラー
	return false, fmt.Errorf("制約を満たすバージョンが見つかりませんでした. 制約: '%s'", requirements)
}
