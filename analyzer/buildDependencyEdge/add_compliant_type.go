package main

import (
	"analyzer/datasource"
	"analyzer/models"
	"analyzer/sv"
	"bufio"
	"database/sql"
	"encoding/csv"
	"fmt"
	"github.com/Masterminds/semver/v3"
	"github.com/cheggaaa/pb/v3"
	_ "github.com/go-sql-driver/mysql"
	"github.com/pkg/errors"
	"os"
	"strings"
	"time"
)

func main() {
	args := os.Args

	err := addCompliantType(args[1])
	if err != nil {
		panic(err)
	}
}

func addCompliantType(outputFileName string) error {
	// 脆弱性のリスト
	file, err := os.Open("dependencies.csv")
	if err != nil {
		return errors.WithStack(err)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			panic(err)
		}
	}(file)

	outputFile, err := os.Create(outputFileName)
	if err != nil {
		return errors.WithStack(err)
	}
	outputFileWriter := csv.NewWriter(outputFile)
	outputFileWriter.Write([]string{
		"id",
		":START_ID",
		":END_ID",
		"dependencyRequirement",
		":TYPE",
		"compliantType",
	})

	db, err := sql.Open("mysql", "root@(localhost:3306)/lib")
	if err != nil {
		return errors.WithStack(err)
	}

	bar := pb.Full.Start(220489689)
	bar.SetRefreshRate(10 * time.Second)

	fr := bufio.NewScanner(file)
	fr.Scan()

	for fr.Scan() {
		row := strings.Split(fr.Text(), ",")
		bar.Increment()

		outputFileWriter.Write([]string{
			row[0],
			row[1],
			row[2],
			row[3],
			row[4],
			fmt.Sprint(parseRow(db, row)),
		})
	}

	return nil
}

func parseRow(db *sql.DB, row []string) models.CompliantType {
	endVersion, err := datasource.GetVersionById(db, row[2], "npm")
	if err != nil {
		return 0
	}

	endVersionNumber, err := semver.NewVersion(endVersion.VersionNumber)
	if err != nil {
		return 0
	}

	compliantType, err := sv.CheckCompliantSemVer(row[3], endVersionNumber)
	if err != nil {
		return 0
	}

	return compliantType
}
