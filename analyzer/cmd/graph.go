package cmd

import (
	"context"
	"encoding/csv"
	"fmt"
	"github.com/cheggaaa/pb/v3"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
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
	PackageId           string        `json:"package_id"`
	IntroducedVersionId int64         `json:"introduced_version_id"`
	IntroducedTimestamp time.Time     `json:"introduced_timestamp"`
	FixedVersionId      int64         `json:"fixed_version_id"`
	FixedTimestamp      time.Time     `json:"fixed_timestamp"`
	RawVulDuration      time.Duration `json:"raw_vul_duration"`
	VulDuration         time.Duration `json:"vul_duration"`
	DependencyId        int64         `json:"dependency_id"`
}

type Neo4jRecord struct {
	AffectedPackageId                          string    `json:"affected_package_id"`
	AffectedPackageVersionId                   int64     `json:"affected_version_id"`
	AffectedPackagePublishTimestamp            time.Time `json:"affected_package_publish_timestamp"`
	AffectedPackageNextVersionId               int64     `json:"affected_version_next_id"`
	AffectedPackageNextVersionPublishTimestamp time.Time `json:"affected_package_next_version_publish_timestamp"`
	DependencyId                               int64     `json:"dependency_id"`
}

func AnalyzeWithGraphDB(vulPackageInputFile string) error {
	vulPackagesOutputFile, err := os.Create("test.csv")
	if err != nil {
		return err
	}
	outputFileWriter := csv.NewWriter(vulPackagesOutputFile)
	if err := writeHeader(outputFileWriter); err != nil {
		return err
	}

	driver, err := neo4j.NewDriverWithContext(neo4jUri, neo4j.BasicAuth("neo4j", "yamoyamoto", ""))
	if err != nil {
		return err
	}
	defer driver.Close(context.Background())

	vulPackages, err := readVulRecords(vulPackageInputFile)
	if err != nil {
		return err
	}

	bar := pb.Full.Start(len(vulPackages))
	for _, vulPackage := range vulPackages {
		bar.Increment()

		log.Println("find affected package versions: ", vulPackage.PackageName)
		affectedPackageVersions, err := findAffectedPackageVersions(driver, vulPackage.VersionsString, 2)
		if err != nil {
			return err
		}
		for _, affectedPackageVersion := range affectedPackageVersions {
			if err := outputFileWriter.Write([]string{
				vulPackage.ID,
				vulPackage.Summary,
				vulPackage.PackageName,
				affectedPackageVersion.PackageId,
				strconv.FormatInt(affectedPackageVersion.IntroducedVersionId, 10),
				strconv.FormatInt(affectedPackageVersion.FixedVersionId, 10),
				strconv.FormatInt(affectedPackageVersion.DependencyId, 10),
				// 単位はday
				strconv.FormatFloat(affectedPackageVersion.VulDuration.Seconds()/3600/24, 'f', -1, 64),
				strconv.FormatFloat(affectedPackageVersion.RawVulDuration.Seconds()/3600/24, 'f', -1, 64),
				//
				affectedPackageVersion.IntroducedTimestamp.String(),
				affectedPackageVersion.FixedTimestamp.String(),
			}); err != nil {
				return err
			}
		}
		outputFileWriter.Flush()
	}

	return nil
}

func ParseIntMust(s string) int64 {
	i, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		panic(err)
	}
	return i
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
RETURN DISTINCT affected_version.package_id AS affected_package_id, affected_version.version_id AS affected_version_id, 
affected_version_next.version_id AS affected_version_next_id, id(dependency[%d]) AS dependency_id,
affected_version.published_timestamp AS affected_version_published_timestamp, affected_version_next.published_timestamp AS affected_version_next_published_timestamp
ORDER BY affected_package_id ASC, dependency_id ASC, affected_version_published_timestamp ASC
LIMIT 100000;
		`, deps, deps, strings.Join(vulPackageVersionIds, ","), deps-1)
		fmt.Printf("query: =====\n\n %s \n\n ====\n", queryString)

		result, err := transaction.Run(ctx, queryString, map[string]any{})
		if err != nil {
			return nil, err
		}

		records := make([]Neo4jRecord, 0)
		for result.Next(ctx) {
			r := result.Record()
			records = append(records, Neo4jRecord{
				AffectedPackageId:                          r.Values[0].(string),
				AffectedPackageVersionId:                   ParseIntMust(r.Values[1].(string)),
				AffectedPackageNextVersionId:               ParseIntMust(r.Values[2].(string)),
				DependencyId:                               r.Values[3].(int64),
				AffectedPackagePublishTimestamp:            r.Values[4].(time.Time),
				AffectedPackageNextVersionPublishTimestamp: r.Values[5].(time.Time),
			})
		}
		log.Printf("neo4jレコード数: %d", len(records))

		return records, result.Err()
	})
	if err != nil {
		return nil, err
	}

	records := rs.([]Neo4jRecord)

	if len(records) > 100000 {
		log.Println("too many records. records count: ", len(records))
		return nil, nil
	}

	vulRecords := make([]VulRecord, 0)
	nowPackageId := ""
	samePackageVulRecords := make([]VulRecord, 0)

	for len(records) != 0 {
		if records[0].AffectedPackageId != nowPackageId {
			// TODO: リフレッシュ
			if _, err := refreshVulRecords(samePackageVulRecords); err != nil {
				return nil, err
			}
			vulRecords = append(vulRecords, samePackageVulRecords...)

			nowPackageId = records[0].AffectedPackageId
			samePackageVulRecords = make([]VulRecord, 0)
		}

		// 今のパッケージの中で、同じ依存関係のものをまとめて，それをもとにfixedVersionを探す
		fixedVersionId, vulDuration, deletingIndexes, err := findFixedVersion(records)
		if err != nil {
			return nil, err
		}
		vukRecord := VulRecord{
			PackageId:           records[0].AffectedPackageId,
			IntroducedVersionId: records[0].AffectedPackageVersionId,
			IntroducedTimestamp: records[0].AffectedPackagePublishTimestamp,
			FixedVersionId:      fixedVersionId,
			FixedTimestamp:      records[0].AffectedPackageNextVersionPublishTimestamp,
			RawVulDuration:      vulDuration,
			VulDuration:         vulDuration,
			DependencyId:        records[0].DependencyId,
		}

		samePackageVulRecords = append(samePackageVulRecords, vukRecord)

		// すでに調べた要素は削除(indexずれるので後ろから消す)
		for i := len(deletingIndexes) - 1; i >= 0; i-- {
			records = append(records[:deletingIndexes[i]], records[deletingIndexes[i]+1:]...)
		}
		records = records[1:]
	}

	log.Printf("脆弱性レコード数: %d", len(vulRecords))
	return vulRecords, nil
}

// 同project_idのものしか入らない
// 前提: IntroducedTimestampが新しい順にソートされている
// memo: https://s3.us-west-2.amazonaws.com/secure.notion-static.com/d3a957bf-bf55-412f-a817-f24f0c344f46/%E7%A0%94%E7%A9%B6%E3%83%A1%E3%83%A2-9.jpg?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIAT73L2G45EIPT3X45%2F20230314%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20230314T021234Z&X-Amz-Expires=86400&X-Amz-Signature=22bc4297680f52aba51b61c11325c1c3da7b8771dbba43591e7a84970463db26&X-Amz-SignedHeaders=host&response-content-disposition=filename%3D%22%25E7%25A0%2594%25E7%25A9%25B6%25E3%2583%25A1%25E3%2583%25A2-9.jpg%22&x-id=GetObject
type durations []duration

type duration struct {
	start time.Time
	end   time.Time
}

func refreshVulRecords(samePackageVulRecords []VulRecord) ([]VulRecord, error) {
	if len(samePackageVulRecords) == 0 {
		return []VulRecord{}, nil
	}

	beforeTime := samePackageVulRecords[0].IntroducedTimestamp
	for i, _ := range samePackageVulRecords {
		if i == 0 {
			continue
		}

		if beforeTime.Equal(samePackageVulRecords[i].IntroducedTimestamp) ||
			beforeTime.After(samePackageVulRecords[i].IntroducedTimestamp) {
			continue
		}
		dul := duration{
			start: beforeTime,
			end:   samePackageVulRecords[i].IntroducedTimestamp,
		}
		beforeTime = samePackageVulRecords[i].IntroducedTimestamp

		if dul.start.Equal(dul.end) {
			continue
		}

		// 範囲の中で被ってるやつ洗い出す
		overlappedIndexes := make([]int, 0)
		for j := 0; j < len(samePackageVulRecords); j++ {
			if i == j {
				continue
			}

			if (samePackageVulRecords[j].IntroducedTimestamp.After(dul.start) ||
				samePackageVulRecords[j].IntroducedTimestamp.Equal(dul.start)) &&
				(samePackageVulRecords[j].IntroducedTimestamp.Before(dul.end) ||
					samePackageVulRecords[j].IntroducedTimestamp.Equal(dul.end)) {
				overlappedIndexes = append(overlappedIndexes, j)
			}

			if samePackageVulRecords[j].IntroducedTimestamp.After(dul.end) {
				break
			}
		}

		//log.Printf("duration: %v~%v", dul.start, dul.end)
		// 被ってるやつで割り算
		for _, j := range overlappedIndexes {
			//log.Printf("dulation: %v, 分母: %v, start_id: %v, end_id: %v",
			//	dul.end.Sub(dul.start).Seconds()/3600/24,
			//	len(overlappedIndexes),
			//	samePackageVulRecords[j].IntroducedVersionId,
			//	samePackageVulRecords[j].FixedVersionId,
			//)

			start := time.Time{}
			if samePackageVulRecords[j].IntroducedTimestamp.After(dul.start) {
				start = samePackageVulRecords[j].IntroducedTimestamp
			} else {
				start = dul.start
			}

			end := time.Time{}
			if samePackageVulRecords[j].FixedTimestamp.Before(dul.end) {
				end = samePackageVulRecords[j].FixedTimestamp
			} else {
				end = dul.end
			}

			samePackageVulRecords[j].VulDuration -= end.Sub(start) /
				(time.Duration(len(overlappedIndexes))) * time.Duration(len(overlappedIndexes)-1)
		}
		//log.Print("\n\n")
	}

	return samePackageVulRecords, nil
}

// 2の方が大きいときは正の値
func getTimestampDiff(timestamp1, timestamp2 time.Time) (time.Duration, error) {
	return timestamp2.Sub(timestamp1), nil
}

func findFixedVersion(records []Neo4jRecord) (int64, time.Duration, []int, error) {
	deletingIndexes := make([]int, 0)
	introducedRecord := records[0]

	dependencyId := introducedRecord.DependencyId
	nextVersionId := introducedRecord.AffectedPackageNextVersionId
	nextPublishTimestamp := introducedRecord.AffectedPackageNextVersionPublishTimestamp

	for i, record := range records {
		// 違うdependencyIdに差し掛かったらbreak
		if record.DependencyId != dependencyId {
			duration, err := getTimestampDiff(introducedRecord.AffectedPackagePublishTimestamp, records[i-1].AffectedPackageNextVersionPublishTimestamp)

			if err != nil {
				return 0, 0, nil, err
			}
			return records[i-1].AffectedPackageNextVersionId, duration, deletingIndexes, nil
		}

		// 同じ依存関係内で途切れるまで探索する
		if nextVersionId == record.AffectedPackageVersionId {
			nextVersionId = record.AffectedPackageNextVersionId
			nextPublishTimestamp = record.AffectedPackageNextVersionPublishTimestamp
			deletingIndexes = append(deletingIndexes, i)
		}
	}

	duration, err := getTimestampDiff(introducedRecord.AffectedPackagePublishTimestamp, nextPublishTimestamp)
	if err != nil {
		return 0, 0, nil, err
	}
	return nextVersionId, duration, deletingIndexes, nil
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

func writeHeader(writer *csv.Writer) error {
	return writer.Write([]string{
		"id",
		"summary",
		"package_name",
		"project_id",
		"vul_start_version",
		"vul_end_version",
		"dependency_id",
		"vul_duration",
		"raw_vul_duration",
		"vul_start_version_published_at",
		"vul_end_version_published_at",
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
