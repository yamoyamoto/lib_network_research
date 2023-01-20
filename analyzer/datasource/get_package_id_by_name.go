package datasource

import (
	"analyzer/models"
	"database/sql"
)

const (
	getPackageIdByName = `
SELECT d.project_id
FROM dependencies_{{.ecosystemType}} d
WHERE d.project_name='{{.projectName}}'
LIMIT 1
`
)

func GetPackageIdByName(db *sql.DB, ecosystem models.EcosystemType, projectName string) (string, error) {
	sqlString, err := buildStringWithParamsFromTemplate(getPackageIdByName, map[string]string{
		"projectName":   projectName,
		"ecosystemType": string(ecosystem),
	})
	if err != nil {
		return "", err
	}

	var projectId string
	if err := db.QueryRow(sqlString).Scan(&projectId); err != nil {
		return "", err
	}

	return projectId, nil
}
