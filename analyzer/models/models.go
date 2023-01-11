package models

type ReleaseLog struct {
	ProjectId              string  `json:"project_id"`
	ProjectName            string  `json:"project_name"`
	VersionId              string  `json:"version_id"`
	VersionNumber          string  `json:"version_number"`
	DependencyRequirements *string `json:"dependency_requirements"`
	PublishedTimestamp     string  `json:"published_timestamp"`
	PackageType            string  `json:"type"`
}
