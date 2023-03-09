package cmd

import (
	"context"
	"encoding/csv"
	"fmt"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"log"
	"os"
	"strconv"
	"strings"
)

const (
	neo4jUri = "neo4j://localhost:7687"
)

type SourceVulRecord struct {
	ID          string
	Summary     string
	PackageName string
	// ;区切りで脆弱性を持つバージョンを列挙
	VersionsString string
	PublishedAt    string
	ProjectId      string
}

type VulRecord struct {
	IntroducedVersionId string `json:"introduced_version_id"`
	FixedVersionId      string `json:"fixed_version_id"`
	DependencyId        int64  `json:"dependency_id"`
}

type Neo4jRecord struct {
	AffectedPackageVersionId     string `json:"affected_version_id"`
	AffectedPackageNextVersionId string `json:"affected_version_next_id"`
	DependencyId                 int64  `json:"dependency_id"`
}

func AnalyzeWithGraphDB(vulPackageInputFile string) error {
	// 脆弱性のリスト
	vulPackagesOutputFile, err := os.Create("test.csv")
	if err != nil {
		return err
	}
	outputFileWriter := csv.NewWriter(vulPackagesOutputFile)
	writeHeader(outputFileWriter)

	driver, err := neo4j.NewDriverWithContext(neo4jUri, neo4j.BasicAuth("neo4j", "yamoyamoto", ""))
	if err != nil {
		return err
	}
	defer driver.Close(context.Background())

	vulPackages, err := readVulRecords(vulPackageInputFile)
	if err != nil {
		return err
	}

	for _, vulPackage := range vulPackages {
		log.Println("find affected package versions: ", vulPackage.PackageName)
		affectedPackageVersions, err := findAffectedPackageVersions(driver, vulPackage.VersionsString, 2)
		if err != nil {
			return err
		}
		for _, affectedPackageVersion := range affectedPackageVersions {
			outputFileWriter.Write([]string{
				vulPackage.ID,
				vulPackage.Summary,
				vulPackage.PackageName,
				vulPackage.ProjectId,
				affectedPackageVersion.IntroducedVersionId,
				affectedPackageVersion.FixedVersionId,
				strconv.FormatInt(affectedPackageVersion.DependencyId, 10),
			})
		}
		outputFileWriter.Flush()
		break
	}

	return nil
}

func findAffectedPackageVersions(driver neo4j.DriverWithContext, VulPackageVersionIdsString string, deps int64) ([]VulRecord, error) {
	vulPackageVersionIds := strings.Split(VulPackageVersionIdsString, ";")
	for i := range vulPackageVersionIds {
		vulPackageVersionIds[i] = fmt.Sprintf(`"%s"`, vulPackageVersionIds[i])
	}

	ctx := context.Background()
	session := driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	rs, err := session.ExecuteRead(ctx, func(transaction neo4j.ManagedTransaction) (any, error) {
		queryString := fmt.Sprintf(`
MATCH (affected_version:verison)-[dependency*%d..%d]->(affecting_version:verison), (affected_version)-[n:next]->(affected_version_next:verison)
WHERE affecting_version.version_id IN [%s]
RETURN DISTINCT affected_version.version_id AS affected_version_id, affected_version_next.version_id AS affected_version_next_id, id(dependency[%d]) AS dependency_id
ORDER BY dependency_id ASC, affected_version_id ASC;
		`, deps, deps, strings.Join(vulPackageVersionIds, ","), deps-1)
		//fmt.Printf("query: =====\n\n %s \n\n ====\n", queryString)

		result, err := transaction.Run(ctx, queryString, map[string]any{})
		if err != nil {
			return nil, err
		}

		records := make([]Neo4jRecord, 0)
		for result.Next(ctx) {
			r := result.Record()
			records = append(records, Neo4jRecord{
				AffectedPackageVersionId:     r.Values[0].(string),
				AffectedPackageNextVersionId: r.Values[1].(string),
				DependencyId:                 r.Values[2].(int64),
			})
		}

		return records, result.Err()
	})
	if err != nil {
		return nil, err
	}

	records := rs.([]Neo4jRecord)
	vulRecords := make([]VulRecord, 0)
	nowDependencyId := int64(0)
	for len(records) != 0 {
		introducedVersionId := records[0].AffectedPackageVersionId
		nowDependencyId = records[0].DependencyId

		fixedVersionId, deletingIndexes := findFixedVersion(records)
		vulRecords = append(vulRecords, VulRecord{
			IntroducedVersionId: introducedVersionId,
			FixedVersionId:      fixedVersionId,
			DependencyId:        nowDependencyId,
		})

		// すでに調べた要素は削除(indexずれるので後ろから消す)
		for i := len(deletingIndexes) - 1; i >= 0; i-- {
			records = append(records[:deletingIndexes[i]], records[deletingIndexes[i]+1:]...)
		}
		records = records[1:]
	}

	log.Printf("脆弱性レコード数: %d", len(vulRecords))
	return vulRecords, nil
}

func findFixedVersion(records []Neo4jRecord) (string, []int) {
	deletingIndexes := make([]int, 0)
	introducedRecord := records[0]

	dependencyId := introducedRecord.DependencyId
	nextVersionId := introducedRecord.AffectedPackageNextVersionId

	for i, record := range records {
		// 違う依存関係に差し掛かったらbreak
		if record.DependencyId != dependencyId {
			return records[i-1].AffectedPackageNextVersionId, deletingIndexes
		}

		// 同じ依存関係内で途切れるまで探索する
		if nextVersionId == record.AffectedPackageVersionId {
			nextVersionId = record.AffectedPackageNextVersionId
			deletingIndexes = append(deletingIndexes, i)
		}
	}

	return nextVersionId, deletingIndexes
}

func buildSourceVulRecords(rows [][]string) []SourceVulRecord {
	vulPackages := make([]SourceVulRecord, 0)
	for i := 1; i < len(rows); i++ {
		vulPackages = append(vulPackages, SourceVulRecord{
			ID:             rows[i][0],
			Summary:        rows[i][1],
			PackageName:    rows[i][2],
			VersionsString: rows[i][3],
			PublishedAt:    rows[i][4],
			ProjectId:      rows[i][5],
		})
	}
	return vulPackages
}

func writeHeader(writer *csv.Writer) {
	writer.Write([]string{
		"id",
		"summary",
		"package_name",
		"project_id",
		"vul_start_version",
		"vul_end_version",
		"dependency_id",
	})
}

func readVulRecords(filePath string) ([]SourceVulRecord, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
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
		return nil, err
	}

	return buildSourceVulRecords(rows), nil
}
