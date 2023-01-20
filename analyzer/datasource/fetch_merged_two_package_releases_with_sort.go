package datasource

import (
	"analyzer/models"
	"database/sql"
)

const (
	mergeTwoPackageReleasesTemplate = `
SELECT d.project_id,d.project_name,d.version_id,v.number AS version_number,d.dependency_requirements,
	   v.published_timestamp, 'package' AS type
FROM dependencies_{{.ecosystemType}} d
INNER JOIN versions_{{.ecosystemType}} v ON d.version_id=v.id
WHERE d.dependency_project_id={{.vulPackageId}} AND d.project_id={{.packageId}}
UNION ALL
SELECT v.project_id, v.project_name, v.id AS version_id, v.number AS version_number, NULL AS dependency_requirements,
	   v.published_timestamp, 'vul_package' AS type
FROM versions_{{.ecosystemType}} v
WHERE v.project_id={{.vulPackageId}}
ORDER BY published_timestamp;
`
)

func FetchMergedTwoPackageReleasesWithSort(db *sql.DB, ecosystem models.EcosystemType, packageId string, vulPackageId string) ([]models.ReleaseLog, error) {
	sqlString, err := buildStringWithParamsFromTemplate(mergeTwoPackageReleasesTemplate, map[string]string{
		"packageId":     packageId,
		"vulPackageId":  vulPackageId,
		"ecosystemType": string(ecosystem),
	})
	if err != nil {
		return nil, err
	}

	rows, err := db.Query(sqlString)
	if err != nil {
		return nil, err
	}
	defer func(rows *sql.Rows) {
		err := rows.Close()
		if err != nil {
			panic(err)
		}
	}(rows)

	// リリース履歴を時系列で取得
	releaseLogs := make([]models.ReleaseLog, 0)
	for rows.Next() {
		var releaseLog models.ReleaseLog

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
			return nil, err
		}

		releaseLogs = append(releaseLogs, releaseLog)
	}

	return releaseLogs, nil
}
