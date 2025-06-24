package main

import (
	"context"
	"fmt"
	ncx "github.com/iami317/nuclei/v3/lib"
	"github.com/iami317/nuclei/v3/pkg/output"
	syncutil "github.com/projectdiscovery/utils/sync"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	sg, err := syncutil.New(syncutil.WithSize(10))
	sg.Add()
	dir := "/Users/meng/go/src/hzbas/bas-attack/cmd/.conf/poc_script"
	c := map[string][]byte{}
	targetUrl := []string{
		"tcp://192.168.102.152:3306",
	}
	writeCallback := func(event *output.ResultEvent) {
		fmt.Println("*******", event.IP, event.Port, event.TemplateID, event.MatcherName)
	}
	ne, err := ncx.NewThreadSafeNucleiEngineCtx(
		context.Background(),
		ncx.DisableUpdateCheck(),
		ncx.WithTemplatesOrWorkflows(ncx.TemplateSources{
			Templates: []string{dir},
		}),
		ncx.WithVerbosity(ncx.VerbosityOptions{
			Verbose: false,
			Debug:   false,
			Silent:  true,
		}),
	)
	if err != nil {
		fmt.Println(err.Error())
	}
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
	go func() {
		defer sg.Done()
		ne.Eng.Parser.CacheTemplates = c
		ne.Eng.LoadTargets(targetUrl, false)
		err = ne.Eng.ExecuteWithCallback(writeCallback)
	}()

	sg.Wait()
	select {}
}
