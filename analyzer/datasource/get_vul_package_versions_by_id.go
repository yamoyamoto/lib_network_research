package datasource

import (
	"analyzer/models"
	"database/sql"
)

const (
	getPackageVersionsByIdSqlTemplate = `
SELECT v.project_id, v.project_name, v.id AS version_id, v.number AS version_number, NULL AS dependency_requirements,
	   v.published_timestamp
FROM versions_{{.ecosystemType}} v
WHERE v.project_id={{.vulPackageId}}
ORDER BY published_timestamp;
`
)

func GetVulPackageVersionsById(db *sql.DB, vulPackageId string, ecosystemType models.EcosystemType) ([]models.ReleaseLog, error) {
	sqlString, err := buildStringWithParamsFromTemplate(getPackageVersionsByIdSqlTemplate, map[string]string{
		"vulPackageId":  vulPackageId,
		"ecosystemType": string(ecosystemType),
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

	releaseLogs := make([]models.ReleaseLog, 0)
	for rows.Next() {
		releaseLog := models.ReleaseLog{
			PackageType: "vul_package",
		}

		err := rows.Scan(
			&releaseLog.ProjectId,
			&releaseLog.ProjectName,
			&releaseLog.VersionId,
			&releaseLog.VersionNumber,
			&releaseLog.DependencyRequirements,
			&releaseLog.PublishedTimestamp,
		)
		if err != nil {
			return nil, err
		}

		releaseLogs = append(releaseLogs, releaseLog)
	}

	return releaseLogs, nil
}
