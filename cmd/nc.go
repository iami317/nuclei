package main

import (
	"context"
	"fmt"
	ncx "github.com/iami317/nuclei/v3/lib"
)

///Users/meng/nuclei-templates/http/cves/2024/CVE-2024-36401.yaml

func main() {
	targetUrl := []string{
		//"http://101.227.53.155:9090",
		"http://27.18.155.146:81",
		//"http://102.32.127.30",
		//"http://124.65.244.230:8081",
		//"http://123.57.72.20:8086",
		//"http://101.132.171.40",
		//"http://59.54.14.247:8082",
	}

	pocPath := []string{"/Users/meng/go/src/hzbas/bas-attack/cmd/.conf/poc_script/用友A++-rectifyauditgadoubt-远程命令执行.yaml"}
	//pocPath := []string{"/Users/meng/nuclei-templates/"}
	//pocPath := []string{"cmd/pocs"}
	ne, err := ncx.NewThreadSafeNucleiEngineCtx(
		context.Background(),
		ncx.WithTemplatesOrWorkflows(ncx.TemplateSources{
			Templates: pocPath,
		}),
		ncx.WithVerbosity(ncx.VerbosityOptions{
			//Verbose: true,
			Debug: true,
		}),
		//ncx.WithInteractshOptions(ncx.InteractshOpts{
		//
		//})
	)
	if err != nil {
		fmt.Println(err)
	}
	//defer ne.Close()

	//ne.Options().Verbose = true
	//ne.Options().Timeout = 3
	//ne.Options().Retries = 1

	//writeCallback := func(event *output.ResultEvent) {
	//	fmt.Println(event.IP, event.Port, event.TemplateID, event.MatcherName)
	//}
	//ne.GlobalResultCallback(writeCallback)
	err = ne.ExecuteNucleiWithOpts(
		targetUrl,
	)
	if err != nil {
		fmt.Println(err)
	}
}
