package main

import (
	"database/sql"
	"fmt"
	"github.com/Masterminds/semver"
	_ "github.com/go-sql-driver/mysql"
	"log"
	"time"
)

func main() {
	if err := haldler(); err != nil {
		log.Fatal(err)
	}
}

type ReleaseLog struct {
	ProjectId              string  `json:"project_id"`
	ProjectName            string  `json:"project_name"`
	VersionId              string  `json:"version_id"`
	VersionNumber          string  `json:"version_number"`
	DependencyRequirements *string `json:"dependency_requirements"`
	PublishedTimestamp     string  `json:"published_timestamp"`
	PackageType            string  `json:"type"`
}

func haldler() error {
	db, err := sql.Open("mysql", "root@(localhost:3306)/lib")
	if err != nil {
		return err
	}

	err = db.Ping()
	if err != nil {
		return err
	}

	rows, err := db.Query(`
	-- 脆弱性を持つパッケージと、脆弱性を持つパッケージに依存するパッケージのバージョン履歴をマージしてソート
	-- TODO: 脆弱性を持つパッケージの方のバージョンを動的に解決する必要がある(プログラム言語で書いたほうが良さそう)
	SELECT d.project_id,d.project_name,d.version_id,v.number AS version_number,d.dependency_requirements,
		   v.published_timestamp, 'package' AS type
	FROM dependencies_cargo d
	INNER JOIN versions_cargo v ON d.version_id=v.id
	WHERE d.dependency_project_id=31296 AND d.project_id=30786
	UNION ALL
	SELECT v.project_id, v.project_name, v.id AS version_id, v.number AS version_number, NULL AS dependency_requirements,
		   v.published_timestamp, 'vul_package' AS type
	FROM versions_cargo v
	WHERE v.project_id=31296
	ORDER BY published_timestamp;
	`)
	defer rows.Close()

	// リリース履歴を時系列で取得
	releaseLogs := make([]ReleaseLog, 0)
	for rows.Next() {
		var releaseLog ReleaseLog

		err := rows.Scan(
			&releaseLog.ProjectId,
			&releaseLog.ProjectName,
			&releaseLog.VersionId,
			&releaseLog.VersionNumber,
			&releaseLog.DependencyRequirements,
			&releaseLog.PublishedTimestamp,
			&releaseLog.PackageType,
		)
		if err != nil {
			return err
		}

		releaseLogs = append(releaseLogs, releaseLog)
	}
	//fmt.Printf("%#v", releaseLogs)

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
			// beforeReleaseには自分も入れる必要がある
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

func findLatestPackageDependencyRequirements(beforeReleases []ReleaseLog) (string, error) {
	for i := len(beforeReleases) - 1; i >= 0; i-- {
		if beforeReleases[i].PackageType == "package" {
			return *beforeReleases[i].DependencyRequirements, nil
		}
	}
	return "", fmt.Errorf("最新の依存関係制約が見つかりませんでした")
}

func isAffectedVulnerabilityWithVulPackage(isAlreadyPublishedPackage bool, beforeReleases []ReleaseLog) (bool, error) {
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

func isAffectedVulnerabilityWithPackage(requirements string, beforeReleases []ReleaseLog) (bool, error) {
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
