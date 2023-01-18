package sv

import (
	"analyzer/models"
	"fmt"
	"github.com/Masterminds/semver"
)

func CheckCompliantSemVer(constraint string, okVersion *semver.Version) (models.CompliantType, error) {
	c, err := semver.NewConstraint(constraint)
	if err != nil {
		return models.UnKnown, err
	}

	if !c.Check(okVersion) {
		return models.UnKnown, fmt.Errorf("got invalid version: %s with constraint: %s", okVersion.String(), constraint)
	}

	if okVersion.Major() == 0 {
		// 初期開発リリース=単一のバージョン指定
		// パッチが上がっても制約を満たしていたら、semver非準拠
		v, err := semver.NewVersion(fmt.Sprintf("%d.%d.%d", okVersion.Major(), okVersion.Minor(), okVersion.Patch()+1))
		if err != nil {
			return models.UnKnown, err
		}
		if c.Check(v) {
			return models.Permissive, nil
		} else {
			return models.Compliant, nil
		}
	} else {
		// 本番開発リリース=パッチ&マイナーアップデートは受け入れる
		// パッチが上がってだめなら、semver非準拠(より厳しい制約)
		vUpPatch, err := semver.NewVersion(fmt.Sprintf("%d.%d.%d", okVersion.Major(), okVersion.Minor(), okVersion.Patch()+1))
		if err != nil {
			return models.UnKnown, err
		}
		if !c.Check(vUpPatch) {
			return models.Restrictive, nil
		}

		// マイナーが上がってだめなら、semver非準拠(より厳しい制約)
		vUpMinor, err := semver.NewVersion(fmt.Sprintf("%d.%d.%d", okVersion.Major(), okVersion.Minor(), okVersion.Patch()+1))
		if err != nil {
			return models.UnKnown, err
		}
		if !c.Check(vUpMinor) {
			return models.Restrictive, nil
		}

		// メジャーが上がってOKなら、semver非準拠(よりゆるい制約)
		vUpMajor, err := semver.NewVersion(fmt.Sprintf("%d.%d.%d", okVersion.Major(), okVersion.Minor(), okVersion.Patch()+1))
		if err != nil {
			return models.UnKnown, err
		}
		if c.Check(vUpMajor) {
			return models.Permissive, nil
		}

		return models.Compliant, nil
	}
}
