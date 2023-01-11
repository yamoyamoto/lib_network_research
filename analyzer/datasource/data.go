package datasource

import (
	"analyzer/models"
	"bytes"
	"database/sql"
	"text/template"
)

const (
	mergeTwoPackageReleasesTemplate = `
SELECT d.project_id,d.project_name,d.version_id,v.number AS version_number,d.dependency_requirements,
	   v.published_timestamp, 'package' AS type
FROM dependencies_cargo d
INNER JOIN versions_cargo v ON d.version_id=v.id
WHERE d.dependency_project_id={{.vulPackageId}} AND d.project_id={{.packageId}}
UNION ALL
SELECT v.project_id, v.project_name, v.id AS version_id, v.number AS version_number, NULL AS dependency_requirements,
	   v.published_timestamp, 'vul_package' AS type
FROM versions_cargo v
WHERE v.project_id={{.vulPackageId}}
ORDER BY published_timestamp;
`
)

func buildMerge2PackageReleases(packageId string, vulPackageId string) (string, error) {
	tpl, err := template.New("").Parse(mergeTwoPackageReleasesTemplate)
	if err != nil {
		return "", err
	}

	buf := new(bytes.Buffer)
	if err := tpl.Execute(buf, map[string]string{
		"packageId":    packageId,
		"vulPackageId": vulPackageId,
	}); err != nil {
		return "", err
	}

	return buf.String(), nil
}

func FetchReleases(db *sql.DB, packageId string, vulPackageId string) ([]models.ReleaseLog, error) {
	sqlString, err := buildMerge2PackageReleases(packageId, vulPackageId)
	if err != nil {
		return nil, err
	}

	rows, err := db.Query(sqlString)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

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
