// Package runner executes the enumeration process.
package runner

var banner = ``

// showBanner is used to show the banner to the user
func showBanner() {
	//gologger.Print().Msgf("%s\n", banner)
	//gologger.Print().Msgf("\t\tprojectdiscovery.io\n\n")
}

// NucleiToolUpdateCallback updates nuclei binary/tool to latest version
func NucleiToolUpdateCallback() {
	//showBanner()
	//updateutils.GetUpdateToolCallback(config.BinaryName, config.Version)()
}

// AuthWithPDCP is used to authenticate with PDCP
func AuthWithPDCP() {
	//showBanner()
	//pdcpauth.CheckNValidateCredentials(config.BinaryName)
}
