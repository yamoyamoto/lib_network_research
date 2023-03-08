package datasource

import (
	"analyzer/models"
	"database/sql"
)

const (
	getVersionSqlTemplate = `
SELECT v.project_id, v.project_name, v.id AS version_id, v.number AS version_number, NULL AS dependency_requirements,
	   v.published_timestamp
FROM versions_{{.ecosystemType}} v
WHERE v.id={{.id}};
`
)

func GetVersionById(db *sql.DB, id string, ecosystemType models.EcosystemType) (*models.ReleaseLog, error) {
	sqlString, err := buildStringWithParamsFromTemplate(getVersionSqlTemplate, map[string]string{
		"id":            id,
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

	rows.Next()
	releaseLog := &models.ReleaseLog{
		PackageType: "package",
	}
	if err := rows.Scan(
		&releaseLog.ProjectId,
		&releaseLog.ProjectName,
		&releaseLog.VersionId,
		&releaseLog.VersionNumber,
		&releaseLog.DependencyRequirements,
		&releaseLog.PublishedTimestamp,
	); err != nil {
		return nil, err
	}

	return releaseLog, nil
}
