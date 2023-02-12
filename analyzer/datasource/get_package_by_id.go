package datasource

import (
	"analyzer/models"
	"database/sql"
)

const (
	getPackageById = `
SELECT d.source_rank
FROM projects d
WHERE d.id='{{.projectId}}'
LIMIT 1
`
)

func GetPackageById(db *sql.DB, projectId string) (*models.Package, error) {
	sqlString, err := buildStringWithParamsFromTemplate(getPackageById, map[string]string{
		"projectId": projectId,
	})
	if err != nil {
		return nil, err
	}

	var sourceRank int64
	if err := db.QueryRow(sqlString).Scan(&sourceRank); err != nil {
		return nil, err
	}

	return &models.Package{SourceRank: sourceRank}, nil
}
