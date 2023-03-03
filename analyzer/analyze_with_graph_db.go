package main

import "analyzer/cmd"

func main() {
	if err := cmd.AnalyzeWithGraphDB(); err != nil {
		panic(err)
	}
}
