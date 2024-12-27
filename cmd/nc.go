package main

import (
	"context"
	"fmt"
	ncx "github.com/iami317/nuclei/v3/lib"
	"github.com/iami317/nuclei/v3/pkg/output"
	"log"
	"sync"
	"time"
)

var ne *ncx.ThreadSafeNucleiEngine

func main() {
	var err error
	ne, err = ncx.NewThreadSafeNucleiEngineCtx(
		context.Background(),
		ncx.WithTemplatesOrWorkflows(ncx.TemplateSources{
			Templates: []string{"/Users/meng/nuclei-templates/"},
		}),
	)
	if err != nil {
		return
	}
	defer ne.Close()
	t := []string{
		"192.168.101.60:22",
		"http://192.168.101.60:48481",
		//"192.168.100.149:8080",
		//"192.168.100.149:3306",
		//"192.168.100.149:10000",
		//"192.168.100.149:5005",
		//"http://192.168.100.149:8082",
		//"192.168.100.149:5984",
		//"http://192.168.100.149:8983",
		//"http://192.168.100.149:80",
	}
	ts := time.Now()
	wg := &sync.WaitGroup{}
	for _, s := range t {
		wg.Add(1)
		fmt.Println("开始执行", s)
		go exec(s, wg)
	}
	wg.Wait()
	fmt.Println("执行耗时：", time.Since(ts).Seconds())
	select {}

}

func exec(s string, wg *sync.WaitGroup) {
	defer wg.Done()
	var err error
	writeCallback := func(event *output.ResultEvent) {
		fmt.Println(event.URL, event.TemplateID, event.Type)
	}
	err = ne.ExecuteNucleiWithOpts(
		[]string{s},
		writeCallback,
		ncx.WithTemplateFilters(ncx.TemplateFilters{
			Tags: []string{"ssh"},
		}),
	)
	if err != nil {
		log.Fatalf("nc 执行Error:%v", err)
		return
	}
}
