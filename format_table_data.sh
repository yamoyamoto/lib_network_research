#bin/bash

mysql -uroot lib -e "
UPDATE dependencies_npm
SET dependency_requirements = REPLACE(dependency_requirements,'latest', '*')
WHERE dependency_requirements='latest';
"