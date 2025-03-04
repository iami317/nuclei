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
		//"http://101.227.53.155:9090",
		//"http://27.18.155.146:81",
		//"http://102.32.127.30",
		//"http://124.65.244.230:8081",
		//"http://123.57.72.20:8086",
		//"http://101.132.171.40",
		//"http://59.54.14.247:8082",
		"http://192.168.101.60:61616",
	}

	defer func() {
		fmt.Println("-----game ovre----")
	}()

	//pocPath := []string{""}
	//pocPath := []string{"/Users/meng/go/src/hzbas/bas-attack/cmd/.conf/poc_script/d3db572b-da11-4ac1-a3de-7f5641c50e13.yaml"}
	pocPath := []string{"/Users/meng/go/src/hzbas/bas-attack/cmd/.conf/poc_script"}
	//pocPath := []string{"cmd/pocs"}
	ne, err := ncx.NewThreadSafeNucleiEngineCtx(context.Background(), ncx.WithTemplatesOrWorkflows(ncx.TemplateSources{
		Templates: pocPath,
	}))
	if err != nil {
		fmt.Println(err)
	}
	defer ne.Close()

	//ne.Options().Timeout = 3
	//ne.Options().Retries = 1

	writeCallback := func(event *output.ResultEvent) {
		fmt.Println("*******", event.IP, event.Port, event.TemplateID, event.MatcherName)
	}
	ne.GlobalResultCallback(writeCallback)
	err = ne.ExecuteNucleiWithOpts(
		targetUrl,
		func(e *ncx.NucleiEngine) error {
			e.Options().Timeout = 1
			e.Options().Retries = 1
			e.Options().Verbose = true
			e.Options().Tags = []string{"apachemq", "ActiveMQ"}
			//e.Options().InteractshURL = "cutugsbadq724bs1mp0gyynq4tfzt9od6.interactsh.server"
			return nil
		},
	)
	if err != nil {
		fmt.Println(err)
	}

}
