package cmd

import (
	"context"
	"fmt"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"log"
	"strings"
	"time"
)

const (
	neo4jUri = "neo4j://localhost:7687"

	// TODO: テスト用なので後で消す
	deps                       = 3
	subGraphName               = "test-graph"
	vulPackageVersionIdsString = "757067;757069;757071;757073;757075;757076;757080;757082;757083;757087;757089;757095;757097;757099;757100;757103;757107;757111;757116;757117;757118;757119;757121;757122;757126;757128;757131;757135;757137;757139;757141;757143;757145;757147;757150;757154;757157;757160;757162;757165;757167;757170;757173;757176;757178;757180;757182;757184;757186;757188;757189;757192;757195;757197;757198;757199;757200;757201;757202;757204;757207;757209;757214;757216;757220;757221;757223;757228;757230;757232;757234;757235;757237;757238;757240;757241;757244;757247;757251;757252;757254;757256;757258;757263;757267;757269;757272;757274;757276;757278;757281;757282;757284;757286;757288;757290;757291;1479949;1712709;2698485;2698486;2698487;2816714;2816715;2816716;2816717;2885230;2914948;2942034;2967539;2967540;2967541;2967542;2997930;3022796;3048131;3073302;3098568;3146228;3175675;3202824;3235587;3260693;3261152;3288578;3288948;3317249;3318048;3330510;3344248;3349944;3373364;3377477;3403679;3407663;3432185;3435873;3463021;3466792;3496751;3525077;3525205;3700014;3713399;3801937;3801950;3830213;3830267;3861459;3861628;3889631;3893704;4148945;4149468;4166106;4184129;4218413;4257062;4257063;4257088;4275046;4293905;4293906;4329832;4330008;4363950;4364627;4398446;4398529;4437850;4437851;4474341;4474570;4598944;4668867;4669221;4706817;4706818;4729495;4746879;4747202;5007892;5007920;5042414;5042415;5062806;5106502;5107141;5149987;5150316;5192132;5192133"
)

type AffectedPackageVersions struct {
	VulPackageId string
	VulName      string

	// 影響を受け始めたバージョン
	FirstVersionId string
	// 影響を受けおわったバージョン
	LastVersionId string
	// 脆弱性影響の深さ
	Deps int64
}

func findAffectedPackageVersions(driver neo4j.DriverWithContext, vulPackageId string, VulPackageVersionIdsString string, VulName string, deps int64) (*AffectedPackageVersions, error) {
	vulPackageVersionIds := strings.Split(VulPackageVersionIdsString, ";")
	for i, _ := range vulPackageVersionIds {
		vulPackageVersionIds[i] = fmt.Sprintf(`"%s"`, vulPackageVersionIds[i])
	}

	ctx := context.Background()

	session := driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	// サブグラフ削除
	if _, err := session.ExecuteWrite(ctx, func(transaction neo4j.ManagedTransaction) (any, error) {
		queryString := fmt.Sprintf(`CALL gds.graph.drop('%s', false) YIELD graphName`, subGraphName)
		fmt.Printf("query: =====\n\n %s \n\n ====\n", queryString)

		result, err := transaction.Run(ctx, queryString, map[string]any{})
		if err != nil {
			return nil, err
		}

		return nil, result.Err()
	}); err != nil {
		return nil, err
	}
	log.Print("サブグラフ削除完了\n\n")

	// サブグラフ作成
	if _, err := session.ExecuteWrite(ctx, func(transaction neo4j.ManagedTransaction) (any, error) {
		now := time.Now()

		queryString := fmt.Sprintf(`
		MATCH (from:verison)-[d:dependency*%d..%d]->(to:verison)
		WHERE to.version_id IN [%s]
		WITH collect(from) as affectedPackageVersions
			CALL gds.graph.project.cypher(
				"%s",
				'UNWIND $nodes AS n RETURN id(n) AS id',
				'MATCH (n)-[r:next]->(m)
					WHERE (n IN $nodes) AND (m IN $nodes)
					RETURN id(n) AS source, id(m) AS target',
				{
					validateRelationships: false,
					parameters: { nodes: affectedPackageVersions }
				}
			) YIELD graphName, nodeCount AS nodes, relationshipCount AS rels
		RETURN graphName, nodes, rels
	`, deps, deps, strings.Join(vulPackageVersionIds, ","), subGraphName)

		fmt.Printf("query: =====\n\n %s \n\n ====\n", queryString)

		result, err := transaction.Run(ctx, queryString, map[string]any{})
		if err != nil {
			return nil, err
		}

		res := make([]any, 0)
		for result.Next(ctx) {
			res = append(res, result.Record())
		}

		//log.Println("サブグラフ作成完了: ", res[0])
		log.Println("実行時間: ", time.Since(now).Seconds(), "s")
		return res, result.Err()
	}); err != nil {
		return nil, err
	}

	// 弱連結成分とともに脆弱性影響を抽出
	wccComponentsRes, err := session.ExecuteWrite(ctx, func(transaction neo4j.ManagedTransaction) (any, error) {
		now := time.Now()

		result, err := transaction.Run(ctx,
			fmt.Sprintf(`
				CALL gds.wcc.stream("%s")
				YIELD nodeId, componentId
				WITH nodeId, componentId
				ORDER BY nodeId ASC
				WITH componentId, collect(nodeId) AS wcc_nodes
				WITH componentId, gds.util.asNode(head(wcc_nodes)) AS start_version, gds.util.asNode(head(reverse(wcc_nodes))) AS end_version
				MATCH (end_version)-[n:next]->(fixed_version:verison)
				RETURN componentId, start_version, fixed_version
					`, subGraphName),
			map[string]any{})
		if err != nil {
			return nil, err
		}

		res := make([]any, 0)
		for result.Next(ctx) {
			res = append(res, result.Record())
		}

		log.Println("弱連結成分抽出完了: ")
		log.Println("実行時間: ", time.Since(now).Seconds(), "s")

		return res, result.Err()
	})
	if err != nil {
		return nil, err
	}

	for i, row := range wccComponentsRes.([]interface{}) {
		r := row.(*neo4j.Record)
		fmt.Printf("%d,  first version: %s (published at: %s) ==> fixed version: %s (fixed at: %s)\n",
			i,
			r.Values[1].(neo4j.Node).Props["number"],
			r.Values[1].(neo4j.Node).Props["published_timestamp"],
			r.Values[2].(neo4j.Node).Props["number"],
			r.Values[2].(neo4j.Node).Props["published_timestamp"],
		)

		if i > 10 {
			break
		}
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

	return nil, nil
}

func AnalyzeWithGraphDB() error {
	vulPackageVersionIds := strings.Split(vulPackageVersionIdsString, ";")
	for i, _ := range vulPackageVersionIds {
		vulPackageVersionIds[i] = fmt.Sprintf(`"%s"`, vulPackageVersionIds[i])
	}

	ctx := context.Background()

	driver, err := neo4j.NewDriverWithContext(neo4jUri, neo4j.BasicAuth("neo4j", "yamoyamoto", ""))
	if err != nil {
		return err
	}
	defer driver.Close(ctx)

	affectedPackageVersions, err := findAffectedPackageVersions(driver, "dummy", vulPackageVersionIdsString, "dummy", 2)
	if err != nil {
		return err
	}

	log.Println(affectedPackageVersions)

	//for _, row := range wccComponentsRes.([]interface{}) {
	//	r := row.(*neo4j.Record)
	//	log.Println(r.Values[0], r.Values[1])
	//}

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
