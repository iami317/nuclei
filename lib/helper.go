package nuclei

import (
	"github.com/iami317/nuclei/v3/pkg/catalog/config"
)

// DefaultConfig is instance of default nuclei configs
// any mutations to this config will be reflected in all nuclei instances (saves some config to disk)
var DefaultConfig *config.Config

func init() {
	DefaultConfig = config.DefaultConfig
}
