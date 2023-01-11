package datasource

import (
	"database/sql"
)

type AffectedPackagesFromVulPackage struct {
	ProjectId string `json:"project_id"`
}

const fetchAffectedPackagesFromVulPackageSqlTemplate = `
SELECT DISTINCT d.project_id
FROM dependencies_cargo d
WHERE d.dependency_project_id={{.vulPackageId}}
`

func FetchAffectedPackagesFromVulPackage(db *sql.DB, vulPackageId string) ([]AffectedPackagesFromVulPackage, error) {
	sqlString, err := buildStringWithParamsFromTemplate(fetchAffectedPackagesFromVulPackageSqlTemplate, map[string]string{
		"vulPackageId": vulPackageId,
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

	packages := make([]AffectedPackagesFromVulPackage, 0)
	for rows.Next() {
		var p AffectedPackagesFromVulPackage

		err := rows.Scan(
			&p.ProjectId,
		)
		if err != nil {
			return nil, err
		}

		packages = append(packages, p)
	}

	return packages, nil
}
