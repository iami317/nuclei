package main

import (
	"context"
	"fmt"
	ncx "github.com/iami317/nuclei/v3/lib"
	"github.com/iami317/nuclei/v3/pkg/output"
)

///Users/meng/nuclei-templates/http/cves/2024/CVE-2024-36401.yaml

func main() {
	targetUrl := []string{
		"http://101.227.53.155:9090",
		"http://27.18.155.146:81",
		"http://102.32.127.30",
		"http://124.65.244.230:8081",
		"http://123.57.72.20:8086",
		"http://101.132.171.40",
		"http://59.54.14.247:8082",
	}

	pocPath := []string{"/Users/meng/go/src/hzbas/bas-attack/cmd/.conf/poc_script"}
	//pocPath := []string{"/Users/meng/nuclei-templates/"}
	//pocPath := []string{"cmd/pocs"}
	ne, _ := ncx.NewNucleiEngineCtx(
		context.Background(),
		ncx.WithTemplatesOrWorkflows(ncx.TemplateSources{
			Templates: pocPath,
		}),
		//ncx.WithVerbosity(ncx.VerbosityOptions{
		//Verbose: true,
		//Debug:   true,
		//}),
		//ncx.WithNetworkConfig(ncx.NetworkConfig{
		//Timeout: 2,
		//Retries: 1,
		//}),

		//nuclei.WithTemplateFilters(nuclei.TemplateFilters{Tags: []string{"oast"}}),
		//nuclei.EnableStatsWithOpts(nuclei.StatsOptions{MetricServerPort: 6064}), // optionally enable metrics server for better observability
	)
	defer ne.Close()
	//ne.Options().Debug = true
	ne.Options().Verbose = true
	ne.Options().Timeout = 3
	ne.Options().Retries = 1
	ne.LoadTargets(targetUrl, false)
	writeCallback := func(event *output.ResultEvent) {
		fmt.Println(event.IP, event.Port, event.TemplateID, event.MatcherName)
	}

	//if taskArguments.PowerStrategy.VerifyStrategy == 1 && len(info.Tags) > 0 { //标签匹配
	//	ne.Options().Tags = info.Tags
	//}
	err := ne.ExecuteWithCallback(writeCallback)
	if err != nil {
		fmt.Println(err)
	}
}
