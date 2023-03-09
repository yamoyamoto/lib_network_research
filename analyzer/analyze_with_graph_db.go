package main

import (
	"analyzer/cmd"
	"os"
)

func main() {
	args := os.Args
	if err := cmd.AnalyzeWithGraphDB(args[1]); err != nil {
		panic(err)
	}
}
