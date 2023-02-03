module analyzer

go 1.19

replace yamoyamoto/phpsemver v0.0.0 => ./../phpsemver

require (
	github.com/go-sql-driver/mysql v1.7.0
	yamoyamoto/phpsemver v0.0.0
)

require github.com/Masterminds/semver/v3 v3.2.0 // indirect
