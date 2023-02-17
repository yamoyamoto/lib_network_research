package main

import (
	"analyzer/datasource"
	"analyzer/models"
	"database/sql"
	"encoding/csv"
	"fmt"
	"github.com/Masterminds/semver/v3"
	"github.com/cheggaaa/pb/v3"
	_ "github.com/go-sql-driver/mysql"
	"log"
	"os"
)

type InputRecord struct {
	ProjectId           string
	DependencyProjectId string
}

func main() {
	if err := handler(); err != nil {
		panic(err)
	}
}

const (
	ecosystemType = "npm"
)

func handler() error {
	file, err := os.Open("inputs.tsv")
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
	r.Comma = '\t'
	rows, err := r.ReadAll()
	if err != nil {
		return err
	}

	// csvからデータ取得
	records := make([]InputRecord, 0)
	for _, row := range rows {
		if len(row) < 2 {
			continue
		}
		records = append(records, InputRecord{
			ProjectId:           row[0],
			DependencyProjectId: row[1],
		})
	}

	outFile, err := os.Create("output.csv")
	if err != nil {
		return err
	}
	outputWriter := csv.NewWriter(outFile)
	outputWriter.Write([]string{
		"packageVersionId",
		"dependencyPackageVersionId",
		"dependencyRequirement",
	})

	log.Println("record count:", len(records))
	db, err := sql.Open("mysql", "root@(localhost:3306)/lib")
	if err != nil {
		return err
	}
	bar := pb.Full.Start(len(records))
	for _, record := range records {
		bar.Increment()

		releases, err := datasource.FetchMergedTwoPackageReleasesWithSort(db, ecosystemType, record.ProjectId, record.DependencyProjectId)
		if err != nil {
			log.Println("some error raised.", err)
			continue
		}

		// バージョン間の依存関係を解析
		latestProjectReleaseIndex := -1
		latestDependencyProjectReleaseIndex := -1
		for i, release := range releases {
			if release.PackageType == "package" {
				// 依存元
				latestProjectReleaseIndex = i

				if latestDependencyProjectReleaseIndex == -1 {
					// 依存可能なリリースが存在しない
					continue
				}

				// 最新から順に遡って、利用可能なものを探す
				usedDependencyPackageRelease, err := findLatestDependencyPackageVersion(releases[0:i], *release.DependencyRequirements)
				if err != nil {
					//log.Println(err)
					continue
				}

				//log.Printf("依存関係が見つかりました. %s:%s -> %s:%s", release.ProjectId, release.VersionNumber, usedDependencyPackageRelease.ProjectId, usedDependencyPackageRelease.VersionNumber)
				outputWriter.Write([]string{
					release.VersionId,
					usedDependencyPackageRelease.VersionId,
					*release.DependencyRequirements,
				})
			} else if release.PackageType == "vul_package" {
				// 依存先
				latestDependencyProjectReleaseIndex = i

				if latestProjectReleaseIndex == -1 {
					// まだ依存関係が定義されていない
					continue
				}

				isSatisfy, err := isSatisfyDependencyRequirement(*releases[latestProjectReleaseIndex].DependencyRequirements, release)
				if err != nil {
					//log.Println(err)
					continue
				}

				if isSatisfy {
					outputWriter.Write([]string{
						releases[latestProjectReleaseIndex].VersionId,
						release.VersionId,
						*releases[latestProjectReleaseIndex].DependencyRequirements,
					})
				}
			} else {
				log.Println("unknown package type.", release)
			}
			outputWriter.Flush()
		}
	}

	outputWriter.Flush()
	return nil
}

func findLatestDependencyPackageVersion(releases []models.ReleaseLog, requirements string) (*models.ReleaseLog, error) {
	for i := len(releases) - 1; i >= 0; i-- {
		if releases[i].PackageType == "vul_package" {
			v, err := semver.NewVersion(releases[i].VersionNumber)
			if err != nil {
				return nil, err
			}
			c, err := semver.NewConstraint(requirements)
			if err != nil {
				return nil, err
			}
			if c.Check(v) {
				return &releases[i], nil
			}
		}
	}
	return nil, fmt.Errorf("利用可能なバージョンが見つかりませんでした")
}

func isSatisfyDependencyRequirement(requirement string, release models.ReleaseLog) (bool, error) {
	v, err := semver.NewVersion(release.VersionNumber)
	if err != nil {
		return false, err
	}
	c, err := semver.NewConstraint(requirement)
	if err != nil {
		return false, err
	}
	return c.Check(v), nil
}
