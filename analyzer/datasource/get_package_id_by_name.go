package datasource

import (
	"database/sql"
)

const (
	getPackageIdByName = `
SELECT d.project_id
FROM dependencies_cargo d
WHERE d.project_name='{{.projectName}}'
LIMIT 1
`
)

func GetPackageIdByName(db *sql.DB, projectName string) (string, error) {
	sqlString, err := buildStringWithParamsFromTemplate(getPackageIdByName, map[string]string{
		"projectName": projectName,
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
