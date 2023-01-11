package datasource

import (
	"bytes"
	"text/template"
)

func buildStringWithParamsFromTemplate(templateString string, params map[string]string) (string, error) {
	tpl, err := template.New("").Parse(templateString)
	if err != nil {
		return "", err
	}

	buf := new(bytes.Buffer)
	if err := tpl.Execute(buf, params); err != nil {
		return "", err
	}

	return buf.String(), nil
}
