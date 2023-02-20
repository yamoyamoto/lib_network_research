package main

import (
	"encoding/csv"
	"fmt"
	"os"
)

func main() {
	if err := parseNextEdges(); err != nil {
		panic(err)
	}
}

type Version struct {
	Id        string
	PackageId string
	Number    string
}

type NextEdge struct {
	Id   string
	From string
	To   string
}

func parseNextEdges() error {
	file, err := os.Open("versions.csv")
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			panic(err)
		}
	}(file)

	r := csv.NewReader(file)
	rows, err := r.ReadAll()
	if err != nil {
		return err
	}

	versions := make([]Version, 0)
	for _, row := range rows {
		versions = append(versions, Version{
			Id:        row[0],
			PackageId: row[1],
			Number:    row[2],
		})
	}

	nextEdges := make([]NextEdge, 0)
	nowVersion := Version{}
	id := 1
	for _, version := range versions {
		if nowVersion.PackageId == version.PackageId {
			nextEdges = append(nextEdges, NextEdge{
				Id:   fmt.Sprintf("%d", id),
				From: nowVersion.Id,
				To:   version.Id,
			})
		}
		nowVersion = version
		id++
	}

	// 出力
	outFile, err := os.Create("next_edges.csv")
	if err != nil {
		return err
	}
	outputWriter := csv.NewWriter(outFile)
	outputWriter.Write([]string{
		"next_edge_id",
		":START_ID",
		":END_ID",
		":TYPE",
	})

	for _, e := range nextEdges {
		outputWriter.Write([]string{
			e.Id,
			e.From,
			e.To,
			"next",
		})
	}

	outputWriter.Flush()

	return nil
}
