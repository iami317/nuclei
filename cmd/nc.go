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
		"http://192.168.101.60:10909",
	}

	defer func() {
		fmt.Println("-----game ovre----")
	}()

	//pocPath := []string{""}
	//pocPath := []string{"/Users/meng/go/src/hzbas/bas-attack/cmd/.conf/poc_script/d3db572b-da11-4ac1-a3de-7f5641c50e13.yaml"}
	pocPath := []string{"/Users/meng/go/src/hzbas/bas-attack/cmd/.conf/poc_script/9b06584d-aaac-499c-919a-aad8eb77cfe0.yaml"}
	//pocPath := []string{"cmd/pocs"}
	ne, err := ncx.NewNucleiEngineCtx(
		context.Background(),
		ncx.WithTemplatesOrWorkflows(ncx.TemplateSources{
			Templates: pocPath,
		}),
		ncx.WithVerbosity(ncx.VerbosityOptions{
			//Silent:  true,
			Verbose: true,
			Debug:   true,
		}),
	)
	if err != nil {
		fmt.Println(err)
	}
	defer ne.Close()
	//ne.GetExecuterOptions().Options.Tags = []string{"epmd", "couchdb"}

	writeCallback := func(event *output.ResultEvent) {
		fmt.Println("*******", event.IP, event.Port, event.TemplateID, event.MatcherName)
	}
	ne.LoadTargets(targetUrl, false)
	err = ne.ExecuteWithCallback(writeCallback)

	if err != nil {
		fmt.Println(err)
	}

}
