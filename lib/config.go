package nuclei

import (
	"github.com/iami317/nuclei/v3/pkg/model/types/severity"
	"github.com/iami317/nuclei/v3/pkg/templates/types"
)

// TemplateSources contains template sources
// which define where to load templates from
type TemplateSources struct {
	Templates       []string // template file/directory paths
	Workflows       []string // workflow file/directory paths
	RemoteTemplates []string // remote template urls
	RemoteWorkflows []string // remote workflow urls
	TrustedDomains  []string // trusted domains for remote templates/workflows
}

// WithTemplatesOrWorkflows sets templates / workflows to use /load
func WithTemplatesOrWorkflows(sources TemplateSources) NucleiSDKOptions {
	return func(e *NucleiEngine) error {
		// by default all of these values are empty
		e.opts.Templates = sources.Templates
		e.opts.Workflows = sources.Workflows
		e.opts.TemplateURLs = sources.RemoteTemplates
		e.opts.WorkflowURLs = sources.RemoteWorkflows
		e.opts.RemoteTemplateDomainList = append(e.opts.RemoteTemplateDomainList, sources.TrustedDomains...)
		return nil
	}
}

// config contains all SDK configuration options
type TemplateFilters struct {
	Severity             string   // filter by severities (accepts CSV values of info, low, medium, high, critical)
	ExcludeSeverities    string   // filter by excluding severities (accepts CSV values of info, low, medium, high, critical)
	ProtocolTypes        string   // filter by protocol types
	ExcludeProtocolTypes string   // filter by excluding protocol types
	Authors              []string // fiter by author
	Tags                 []string // filter by tags present in template
	ExcludeTags          []string // filter by excluding tags present in template
	IncludeTags          []string // filter by including tags present in template
	IDs                  []string // filter by template IDs
	ExcludeIDs           []string // filter by excluding template IDs
	TemplateCondition    []string // DSL condition/ expression
}

// WithTemplateFilters sets template filters and only templates matching the filters will be
// loaded and executed
func WithTemplateFilters(filters TemplateFilters) NucleiSDKOptions {
	return func(e *NucleiEngine) error {
		s := severity.Severities{}
		if err := s.Set(filters.Severity); err != nil {
			return err
		}
		es := severity.Severities{}
		if err := es.Set(filters.ExcludeSeverities); err != nil {
			return err
		}
		pt := types.ProtocolTypes{}
		if err := pt.Set(filters.ProtocolTypes); err != nil {
			return err
		}
		ept := types.ProtocolTypes{}
		if err := ept.Set(filters.ExcludeProtocolTypes); err != nil {
			return err
		}
		e.opts.Authors = filters.Authors
		e.opts.Tags = filters.Tags
		e.opts.ExcludeTags = filters.ExcludeTags
		e.opts.IncludeTags = filters.IncludeTags
		e.opts.IncludeIds = filters.IDs
		e.opts.ExcludeIds = filters.ExcludeIDs
		e.opts.Severities = s
		e.opts.ExcludeSeverities = es
		e.opts.Protocols = pt
		e.opts.ExcludeProtocols = ept
		e.opts.IncludeConditions = filters.TemplateCondition
		return nil
	}
}
