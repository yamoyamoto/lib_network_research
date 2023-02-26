package cmd

import (
	"context"
	"fmt"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"log"
)

const (
	neo4jUri = "neo4j://localhost:7687"

	// TODO: テスト用なので後で消す
	deps                = 1
	subGraphName        = "test-graph"
	vulPackageVersionId = "757067"
)

func AnalyzeWithGraphDB() error {
	//now := time.Now()

	ctx := context.Background()

	driver, err := neo4j.NewDriverWithContext(neo4jUri, neo4j.BasicAuth("neo4j", "yamoyamoto", ""))
	if err != nil {
		return err
	}
	defer driver.Close(ctx)

	session := driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	// サブグラフ削除
	_, err = session.ExecuteWrite(ctx, func(transaction neo4j.ManagedTransaction) (any, error) {
		queryString := fmt.Sprintf(`CALL gds.graph.drop('%s', false) YIELD graphName`, subGraphName)
		fmt.Printf("query: =====\n\n %s \n\n ====\n", queryString)

		result, err := transaction.Run(ctx, queryString, map[string]any{})
		if err != nil {
			return nil, err
		}

		return nil, result.Err()
	})
	if err != nil {
		return err
	}
	log.Print("サブグラフ削除完了\n\n")

	// サブグラフ作成
	createSubGraphRes, err := session.ExecuteWrite(ctx, func(transaction neo4j.ManagedTransaction) (any, error) {
		queryString := fmt.Sprintf(`
	MATCH (from:verison)-[d:dependency*%d..%d]->(to:verison)
	WHERE to.id="%s"
	WITH collect(from) as affectedPackageVersions
		CALL gds.graph.project.cypher(
			"%s",
			'UNWIND $nodes AS n RETURN id(n) AS id, labels(n) AS labels',
			'MATCH (n)-[r:next]->(m)
				WHERE (n IN $nodes) AND (m IN $nodes)
				RETURN id(n) AS source, id(m) AS target',
			{
				validateRelationships: false,
				parameters: { nodes: affectedPackageVersions }
			}
		) YIELD graphName, nodeCount AS nodes, relationshipCount AS rels
	RETURN graphName, nodes, rels
`, deps, deps, vulPackageVersionId, subGraphName)

		fmt.Printf("query: =====\n\n %s \n\n ====\n", queryString)

		result, err := transaction.Run(ctx, queryString, map[string]any{})
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
	log.Println("サブグラフ作成完了: ", createSubGraphRes.([]interface{})[0])

	// 弱連結成分とともに脆弱性影響を抽出
	wccComponentsRes, err := session.ExecuteWrite(ctx, func(transaction neo4j.ManagedTransaction) (any, error) {
		result, err := transaction.Run(ctx,
			fmt.Sprintf(`
	CALL gds.wcc.stream("%s")
	YIELD nodeId, componentId
	RETURN nodeId, componentId
`, subGraphName),
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

	for _, row := range wccComponentsRes.([]interface{}) {
		r := row.(*neo4j.Record)
		log.Println(r.Values[0], r.Values[1])
	}

	//for _, row := range wccComponentsRes.([]interface{}) {
	//	r := row.(*neo4j.Record)
	//	log.Printf("source project id:%s(%s) -> affected project id:%s(%s) -> fixed version: %s \n\n",
	//		r.Values[0].(neo4j.Node).Props["nodeId"],
	//		r.Values[0].(neo4j.Node).Props["componentId"],
	//		r.Values[1].(neo4j.Node).Props["package_id"],
	//		r.Values[1].(neo4j.Node).Props["number"],
	//		r.Values[2].(neo4j.Node).Props["number"],
	//	)
	//}

	return nil
}
