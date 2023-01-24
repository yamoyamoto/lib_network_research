package main

import (
	"analyzer/datasource"
	"analyzer/models"
	"analyzer/sv"
	"database/sql"
	"encoding/csv"
	"fmt"
	semver "github.com/Masterminds/semver/v3"
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

type VulPackage struct {
	PackageId     string
	PackageName   string
	VulConstraint string
	Deps          int64
}

func handler() error {
	args := os.Args
	vulPackgeInputFile := args[1]
	outputFile := args[2]
	ecosystemType := models.EcosystemType(args[3])

	db, err := sql.Open("mysql", "root@(localhost:3306)/lib")
	if err != nil {
		return err
	}

	// 脆弱性のリスト
	file, err := os.Open(vulPackgeInputFile)
	if err != nil {
		log.Fatal(err)
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
		log.Fatal(err)
	}

	vulPackages := make([]VulPackage, 0)
	for i := len(rows) - 1; i >= 0; i-- {
		projectId, err := datasource.GetPackageIdByName(db, ecosystemType, rows[i][1])
		if err != nil {
			log.Printf("エラーが発生しました. error: %s", err)
			continue
		}
		vulPackages = append(vulPackages, VulPackage{
			PackageId:     projectId,
			PackageName:   rows[i][1],
			VulConstraint: rows[i][2],
			Deps:          0,
		})
	}

	vulPackagesOutputFile, err := os.Create("vul_packages_npm.csv")
	if err != nil {
		return err
	}
	vulPackagesOutputFileWriter := csv.NewWriter(vulPackagesOutputFile)
	vulPackagesOutputFileWriter.Write([]string{
		"vulPackageId",
		"vulPakageName",
		"vulConstraint",
		"affectedVulCount",
	})

	affectedPackagesOutputFile, err := os.Create(outputFile)
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

	for len(vulPackages) != 0 {
		affectedVulCount := 0

		vulPakageName := vulPackages[0].PackageName
		vulPackageId := vulPackages[0].PackageId
		vulPackageDeps := vulPackages[0].Deps
		vulConstraint := vulPackages[0].VulConstraint
		vulPackages = vulPackages[1:]

		// 深さ制限
		if vulPackageDeps > 0 {
			continue
		}

		// vulPackageに依存しているパッケージを全て取得
		packages, err := datasource.FetchAffectedPackagesFromVulPackage(db, ecosystemType, vulPackageId)
		if err != nil {
			return err
		}
		log.Printf("脆弱性を持ったパッケージ(%s)に依存しているパッケージが %d 個見つかりました", vulPackageId, len(packages))

		for i, p := range packages {
			log.Printf("未解析脆弱パッケージ残り: %d 個の %d/%d   now: %s (%s), 見つかった脆弱性の数: %d", len(vulPackages), i, len(packages), vulPakageName, vulConstraint, affectedVulCount)
			results, err := analyzeVulnerabilityDuration(db, p.ProjectId, vulPackageId, vulConstraint, ecosystemType)
			if err != nil {
				log.Printf("エラーが発生しました. error: %s", err)
				continue
			}
			affectedPackage, err := datasource.GetPackageById(db, p.ProjectId)
			if err != nil {
				log.Printf("エラーが発生しました. error: %s", err)
				continue
			}
			for _, r := range results {
				affectedVulCount++
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
					strconv.FormatInt(int64(r.CompliantType), 10),
					r.VulStartDependencyRequirement,
					r.VulStartVersion.String(),
					strconv.FormatInt(vulPackageDeps, 10),
					strconv.FormatInt(int64(len(results)), 10),
					strconv.FormatInt(affectedPackage.SourceRank, 10),
				}); err != nil {
					return err
				}
				//fmt.Printf("package %s: %s〜%s\n", p.ProjectId, r.VulStartDate.String(), endDate)

				// 推移的な依存関係は後考える
				//vulPackages = append(vulPackages, VulPackage{
				//	PackageId:     r.PackageId,
				//	VulConstraint: fmt.Sprintf("%s - %s", r.VulStartVersion, r.VulEndVersion),
				//	Deps:          vulPackageDeps + 1,
				//})
			}
		}
		vulPackagesOutputFileWriter.Write([]string{
			vulPackageId,
			vulPakageName,
			vulConstraint,
			strconv.FormatInt(int64(affectedVulCount), 10),
		})
		w.Flush()
		vulPackagesOutputFileWriter.Flush()
	}
	vulPackagesOutputFileWriter.Flush()
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

func analyzeVulnerabilityDuration(db *sql.DB, packageId string, vulPackageId string, vulConstraint string, ecosystemType models.EcosystemType) ([]AnalyzeVulnerabilityDurationResult, error) {
	releaseLogs, err := datasource.FetchMergedTwoPackageReleasesWithSort(db, ecosystemType, packageId, vulPackageId)
	if err != nil {
		return nil, err
	}

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
