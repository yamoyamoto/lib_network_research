package cmd

import (
	"context"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"log"
)

const (
	neo4jUri = "neo4j://localhost:7687"
)

func AnalyzeWithGraphDB() error {
	ctx := context.Background()

	driver, err := neo4j.NewDriverWithContext(neo4jUri, neo4j.BasicAuth("neo4j", "yamoyamoto", ""))
	if err != nil {
		return err
	}
	defer driver.Close(ctx)

	session := driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	greeting, err := session.ExecuteWrite(ctx, func(transaction neo4j.ManagedTransaction) (any, error) {
		result, err := transaction.Run(ctx,
			//"MATCH (p)-[r:dependency*1..4]->(v:verison{package_id:\"158021\"}) RETURN p,r,v",
			"MATCH p = (from:verison)-[r:dependency]->(to:verison)-[n:next]->(fixed:verison)"+
				"WHERE to.id=\"474521\" OR to.id=\"540773\" "+
				//"WITH "+
				" RETURN from, to, fixed"+
				" LIMIT 25",
			map[string]any{})
		if err != nil {
			return nil, err
		}

		res := make([]any, 0)
		for result.Next(ctx) {
			res = append(res, result.Record())
		}

		return res, result.Err()
	})
	if err != nil {
		return err
	}

	for _, row := range greeting.([]interface{}) {
		r := row.(*neo4j.Record)
		log.Printf("source project id:%s(%s) -> affected project id:%s(%s) -> fixed version: %s \n\n",
			r.Values[0].(neo4j.Node).Props["package_id"],
			r.Values[0].(neo4j.Node).Props["number"],
			r.Values[1].(neo4j.Node).Props["package_id"],
			r.Values[1].(neo4j.Node).Props["number"],
			r.Values[2].(neo4j.Node).Props["number"],
		)
	}

	return nil
}
