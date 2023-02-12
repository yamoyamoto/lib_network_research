package datasource

import (
	"analyzer/models"
	"database/sql"
)

const fetchAffectedPackagesWithVersionsSqlTemplate = `
SELECT d.project_id,d.project_name,d.version_id,v.number AS version_number,d.dependency_requirements,
	   v.published_timestamp
FROM dependencies_{{.ecosystemType}} d
INNER JOIN versions_{{.ecosystemType}} v ON d.version_id=v.id
WHERE d.dependency_project_id={{.vulPackageId}}
ORDER BY d.project_id ASC, v.published_timestamp ASC
`

func FetchAffectedPackagesWithVersions(db *sql.DB, ecosystem models.EcosystemType, vulPackageId string) (map[string][]models.ReleaseLog, error) {
	sqlString, err := buildStringWithParamsFromTemplate(fetchAffectedPackagesWithVersionsSqlTemplate, map[string]string{
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

	allReleaseLogs := make(map[string][]models.ReleaseLog, 0)
	releaseLogs := make([]models.ReleaseLog, 0)
	nowProjectId := ""
	for rows.Next() {
		releaseLog := models.ReleaseLog{
			PackageType: "package",
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

		if releaseLog.ProjectId != nowProjectId {
			// 次のパッケージ
			allReleaseLogs[releaseLog.ProjectId] = releaseLogs

			releaseLogs = []models.ReleaseLog{releaseLog}
			nowProjectId = releaseLog.ProjectId
		} else {
			// 今までと同じパッケージ
			releaseLogs = append(releaseLogs, releaseLog)
		}
	}

	return allReleaseLogs, nil
}
