package main

import (
	"analyzer/datasource"
	"database/sql"
	"fmt"
	"github.com/Masterminds/semver"
	_ "github.com/go-sql-driver/mysql"
	"log"
	"time"
)

func main() {
	if err := handler(); err != nil {
		log.Fatal(err)
	}
}

func handler() error {
	db, err := sql.Open("mysql", "root@(localhost:3306)/lib")
	if err != nil {
		return err
	}

	releaseLogs, err := datasource.FetchReleases(db, "30786", "31296")
	if err != nil {
		return err
	}

	// 脆弱性の影響を受けていた期間を特定
	// 変数: 脆弱性の始まりと終わりのバージョン
	isAlreadyPublishedPackage := false
	nowAffectedVulnerability := false
	var affectedVulnerabilityStartDate *time.Time

	for i, releaseLog := range releaseLogs {
		if releaseLog.PackageType == "package" {
			// 依存元のパッケージ
			isAffectedVulnerability, err := isAffectedVulnerabilityWithPackage(*releaseLog.DependencyRequirements, releaseLogs[0:i])
			if err != nil {
				return err
			}
			if isAffectedVulnerability {
				if !nowAffectedVulnerability {
					d, err := time.Parse("2006-01-02 15:04:05", releaseLog.PublishedTimestamp)
					if err != nil {
						return err
					}
					affectedVulnerabilityStartDate = &d
					nowAffectedVulnerability = true

					fmt.Printf("脆弱性の影響を受けはじめた. 受けはじめの時刻: %s\n", affectedVulnerabilityStartDate.String())
				}
				// 継続して脆弱性の影響を受けている
			} else {
				if nowAffectedVulnerability {
					affectedVulnerabilityEndDate, err := time.Parse("2006-01-02 15:04:05", releaseLogs[i].PublishedTimestamp)
					if err != nil {
						return err
					}
					fmt.Printf("脆弱性の影響を受け終わった. 受け終わりの時刻: %s\n", affectedVulnerabilityEndDate.String())

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
				return err
			}
			if isAffectedVulnerability {
				if !nowAffectedVulnerability {
					d, err := time.Parse("2006-01-02 15:04:05", releaseLog.PublishedTimestamp)
					if err != nil {
						return err
					}
					affectedVulnerabilityStartDate = &d
					nowAffectedVulnerability = true

					fmt.Printf("脆弱性の影響を受けはじめた. 受けはじめの時刻: %s\n", affectedVulnerabilityStartDate.String())
				}
				// 継続して脆弱性の影響を受けている
			} else {
				if nowAffectedVulnerability {
					affectedVulnerabilityEndDate, err := time.Parse("2006-01-02 15:04:05", releaseLogs[i].PublishedTimestamp)
					if err != nil {
						return err
					}
					fmt.Printf("脆弱性の影響を受け終わった!! 受け終わりの時刻: %s\n", affectedVulnerabilityEndDate.String())

					// 状態を初期化
					nowAffectedVulnerability = false
					affectedVulnerabilityStartDate = nil
				}
			}
		} else {
			return fmt.Errorf("got unknown type of package. type: %s", releaseLog.PackageType)
		}

		// ログ
		//fmt.Printf("今、脆弱性の影響を受けている?: %v\n", nowAffectedVulnerability)
	}

	return nil
}

const (
	vulConstraint = "0.1.6 - 0.1.9"
)

func findLatestPackageDependencyRequirements(beforeReleases []datasource.ReleaseLog) (string, error) {
	for i := len(beforeReleases) - 1; i >= 0; i-- {
		if beforeReleases[i].PackageType == "package" {
			return *beforeReleases[i].DependencyRequirements, nil
		}
	}
	return "", fmt.Errorf("最新の依存関係制約が見つかりませんでした")
}

func isAffectedVulnerabilityWithVulPackage(isAlreadyPublishedPackage bool, beforeReleases []datasource.ReleaseLog) (bool, error) {
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

func isAffectedVulnerabilityWithPackage(requirements string, beforeReleases []datasource.ReleaseLog) (bool, error) {
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
