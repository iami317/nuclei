package main

import (
	"context"
	"fmt"
	ncx "github.com/iami317/nuclei/v3/lib"
	"github.com/iami317/nuclei/v3/pkg/output"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

// /Users/meng/nuclei-templates/http/cves/2024/CVE-2024-36401.yaml

func main() {
	fmt.Println()
	targetUrl := []string{
		"http://192.168.101.60:10909",
	}

	defer func() {
		fmt.Println("-----game ovre----")
	}()

	c := map[string][]byte{}
	//pocPath := []string{""}
	pocPath := []string{"/Users/meng/go/src/hzbas/bas-attack/cmd/.conf/poc_script"}
	dir := "/Users/meng/go/src/hzbas/bas-attack/cmd/.conf/poc_script"
	entries, err := os.ReadDir(dir)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			data, _ := ioutil.ReadFile(filepath.Join(dir, name))
			c[filepath.Join(dir, name)] = data
		}
	}

	ne, err := ncx.NewNucleiEngineCtx(
		context.Background(),
		ncx.WithTemplatesOrWorkflows(ncx.TemplateSources{
			Templates: pocPath,
		}),
		ncx.WithVerbosity(ncx.VerbosityOptions{
			Verbose: false,
			Debug:   false,
		}),
	)
	ne.Parser.CacheTemplates = c
	if err != nil {
		fmt.Println(err)
	}
	defer ne.Close()

	writeCallback := func(event *output.ResultEvent) {
		fmt.Println("*******", event.IP, event.Port, event.TemplateID, event.MatcherName)
	}

	ne.LoadTargets(targetUrl, false)
	err = ne.ExecuteWithCallback(writeCallback)

	if err != nil {
		fmt.Println(err)
	}

}
