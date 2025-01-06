package main

import (
	"context"
	"fmt"
	ncx "github.com/iami317/nuclei/v3/lib"
	"github.com/iami317/nuclei/v3/pkg/output"
)

///Users/meng/nuclei-templates/http/cves/2024/CVE-2024-36401.yaml

func main() {
	targetUrl := "http://192.168.100.139:8080"

	pocPath := "/Users/meng/nuclei-templates/http/cves/2024/CVE-2024-36401.yaml"

	// 创建nuclei引擎对象,设置只扫描http服务漏洞模板
	var ctx = context.Background()
	var ne, err = ncx.NewNucleiEngineCtx(ctx,
		//nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{Templates: []string{`C:\Users\Administrator\nuclei-templates\http\cves\2017\CVE-2017-9805.yaml`}}),
		//nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{RemoteTemplates: []string{poc_path}}),
		ncx.WithTemplatesOrWorkflows(ncx.TemplateSources{Templates: []string{pocPath}}),
		//nuclei.WithTemplateFilters(nuclei.TemplateFilters{IDs: []string{`CVE-2017-9805`}}),
	)
	if err != nil {
		panic(err)
	}

	// 设置扫描目标，这里是一个字符串切片，可以同时扫描多个

	ne.LoadTargets([]string{targetUrl}, false)
	ne.Options().StoreResponse = true
	// 设置扫描出漏洞的回调函数，用results变量保存漏洞
	results := make([]*output.ResultEvent, 0)
	WriteCallback := func(event *output.ResultEvent) {
		if len(event.Response) > 0 {
			//fmt.Println(event.Response)
			fmt.Println("目标存在漏洞")
			event.Response = event.Response[:0]
			fmt.Println("vul_id", event.TemplateID)
			fmt.Println("event.URL" + event.URL)
			fmt.Println("event.TemplateURL" + event.TemplateURL)
			fmt.Println("event.Matched" + event.Matched)
		} else {
			fmt.Println("No Result")
		}
		results = append(results, event)
	}
	// 执行扫描
	err = ne.ExecuteWithCallback(WriteCallback)
	if err != nil {
		panic(err)
	}
	defer ne.Close()
}
