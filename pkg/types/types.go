package types

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/iami317/nuclei/v3/pkg/catalog"
	"github.com/iami317/nuclei/v3/pkg/catalog/config"
	"github.com/iami317/nuclei/v3/pkg/model/types/severity"
	"github.com/iami317/nuclei/v3/pkg/templates/types"
	"github.com/projectdiscovery/goflags"
	errorutil "github.com/projectdiscovery/utils/errors"
	fileutil "github.com/projectdiscovery/utils/file"
	folderutil "github.com/projectdiscovery/utils/folder"
	unitutils "github.com/projectdiscovery/utils/unit"
)

var (
	// ErrNoMoreRequests is internal error to indicate that generator has no more requests to generate
	ErrNoMoreRequests = io.EOF
)

// LoadHelperFileFunction can be used to load a helper file.
type LoadHelperFileFunction func(helperFile, templatePath string, catalog catalog.Catalog) (io.ReadCloser, error)

// Options contains the configuration options for nuclei scanner.
type Options struct {
	// Tags contains a list of tags to execute templates for. Multiple paths
	// can be specified with -l flag and -tags can be used in combination with
	// the -l flag.
	Tags goflags.StringSlice `json:"tags"`
	// ExcludeTags is the list of tags to exclude
	ExcludeTags goflags.StringSlice `json:"exclude_tags"`
	// Workflows specifies any workflows to run by nuclei
	Workflows goflags.StringSlice `json:"workflows"`
	// WorkflowURLs specifies URLs to a list of workflows to use
	WorkflowURLs goflags.StringSlice `json:"workflow_ur_ls"`
	// Templates specifies the template/templates to use
	Templates goflags.StringSlice `json:"templates"`
	// TemplateURLs specifies URLs to a list of templates to use
	TemplateURLs goflags.StringSlice `json:"template_ur_ls"`
	// RemoteTemplates specifies list of allowed URLs to load remote templates from
	RemoteTemplateDomainList goflags.StringSlice `json:"remote_template_domain_list"`
	// 	ExcludedTemplates  specifies the template/templates to exclude
	ExcludedTemplates goflags.StringSlice `json:"excluded_templates"`
	// ExcludeMatchers is a list of matchers to exclude processing
	ExcludeMatchers goflags.StringSlice `json:"exclude_matchers"`
	// CustomHeaders is the list of custom global headers to send with each request.
	CustomHeaders goflags.StringSlice `json:"custom_headers"`
	// Vars is the list of custom global vars
	Vars goflags.RuntimeMap `json:"vars"`
	// Severities filters templates based on their severity and only run the matching ones.
	Severities severity.Severities `json:"severities"`
	// ExcludeSeverities specifies severities to exclude
	ExcludeSeverities severity.Severities `json:"exclude_severities"`
	// Authors filters templates based on their author and only run the matching ones.
	Authors goflags.StringSlice `json:"authors"`
	// Protocols contains the protocols to be allowed executed
	Protocols types.ProtocolTypes `json:"protocols"`
	// ExcludeProtocols contains protocols to not be executed
	ExcludeProtocols types.ProtocolTypes `json:"exclude_protocols"`
	// IncludeTags includes specified tags to be run even while being in denylist
	IncludeTags goflags.StringSlice `json:"include_tags"`
	// IncludeTemplates includes specified templates to be run even while being in denylist
	IncludeTemplates goflags.StringSlice `json:"include_templates"`
	// IncludeIds includes specified ids to be run even while being in denylist
	IncludeIds goflags.StringSlice `json:"include_ids"`
	// ExcludeIds contains templates ids to not be executed
	ExcludeIds goflags.StringSlice `json:"exclude_ids"`
	// InternalResolversList is the list of internal resolvers to use
	InternalResolversList []string `json:"internal_resolvers_list"`
	// ProjectPath allows nuclei to use a user defined project folder
	ProjectPath string `json:"project_path"`
	// InteractshURL is the URL for the interactsh server.
	InteractshURL string `json:"interactsh_url"`
	// Interactsh Authorization header value for self-hosted servers
	InteractshToken string `json:"interactsh_token"`
	// Target URLs/Domains to scan using a template
	Targets goflags.StringSlice `json:"targets"`
	// ExcludeTargets URLs/Domains to exclude from scanning
	ExcludeTargets goflags.StringSlice `json:"exclude_targets"`
	// TargetsFilePath specifies the targets from a file to scan using templates.
	TargetsFilePath string `json:"targets_file_path"`
	// Resume the scan from the state stored in the resume config file
	Resume string `json:"resume"`
	// Output is the file to write found results to.
	Output string `json:"output"`
	// ProxyInternal requests
	ProxyInternal bool `json:"proxy_internal"`
	// Show all supported DSL signatures
	ListDslSignatures bool `json:"list_dsl_signatures"`
	// List of HTTP(s)/SOCKS5 proxy to use (comma separated or file input)
	Proxy goflags.StringSlice `json:"proxy"`
	// AliveProxy is the alive proxy to use
	AliveHttpProxy string `json:"alive_http_proxy"`
	// AliveSocksProxy is the alive socks proxy to use
	AliveSocksProxy string `json:"alive_socks_proxy"`
	// TemplatesDirectory is the directory to use for storing templates
	NewTemplatesDirectory string `json:"new_templates_directory"`
	// TraceLogFile specifies a file to write with the trace of all requests
	TraceLogFile string `json:"trace_log_file"`
	// ErrorLogFile specifies a file to write with the errors of all requests
	ErrorLogFile string `json:"error_log_file"`
	// ReportingDB is the db for report storage as well as deduplication
	ReportingDB string `json:"reporting_db"`
	// ReportingConfig is the config file for nuclei reporting module
	ReportingConfig string `json:"reporting_config"`
	// MarkdownExportDirectory is the directory to export reports in Markdown format
	MarkdownExportDirectory string `json:"markdown_export_directory"`
	// MarkdownExportSortMode is the method to sort the markdown reports (options: severity, template, host, none)
	MarkdownExportSortMode string `json:"markdown_export_sort_mode"`
	// SarifExport is the file to export sarif output format to
	SarifExport string `json:"sarif_export"`
	// ResolversFile is a file containing resolvers for nuclei.
	ResolversFile string `json:"resolvers_file"`
	// StatsInterval is the number of seconds to display stats after
	StatsInterval int `json:"stats_interval"`
	// MetricsPort is the port to show metrics on
	MetricsPort int `json:"metrics_port"`
	// MaxHostError is the maximum number of errors allowed for a host
	MaxHostError int `json:"max_host_error"`
	// TrackError contains additional error messages that count towards the maximum number of errors allowed for a host
	TrackError goflags.StringSlice `json:"track_error"`
	// NoHostErrors disables host skipping after maximum number of errors
	NoHostErrors bool `json:"no_host_errors"`
	// BulkSize is the of targets analyzed in parallel for each template
	BulkSize int `json:"bulk_size"`
	// TemplateThreads is the number of templates executed in parallel
	TemplateThreads int `json:"template_threads"`
	// HeadlessBulkSize is the of targets analyzed in parallel for each headless template
	HeadlessBulkSize int `json:"headless_bulk_size"`
	// HeadlessTemplateThreads is the number of headless templates executed in parallel
	HeadlessTemplateThreads int `json:"headless_template_threads"`
	// Timeout is the seconds to wait for a response from the server.
	Timeout int `json:"timeout"`
	// Retries is the number of times to retry the request
	Retries int `json:"retries"`
	// Rate-Limit is the maximum number of requests per specified target
	RateLimit int `json:"rate_limit"`
	// Rate Limit Duration interval between burst resets
	RateLimitDuration time.Duration `json:"rate_limit_duration"`
	// Rate-Limit is the maximum number of requests per minute for specified target
	// Deprecated: Use RateLimitDuration - automatically set Rate Limit Duration to 60 seconds
	RateLimitMinute int `json:"rate_limit_minute"`
	// PageTimeout is the maximum time to wait for a page in seconds
	PageTimeout int `json:"page_timeout"`
	// InteractionsCacheSize is the number of interaction-url->req to keep in cache at a time.
	InteractionsCacheSize int `json:"interactions_cache_size"`
	// InteractionsPollDuration is the number of seconds to wait before each interaction poll
	InteractionsPollDuration int `json:"interactions_poll_duration"`
	// Eviction is the number of seconds after which to automatically discard
	// interaction requests.
	InteractionsEviction int `json:"interactions_eviction"`
	// InteractionsCoolDownPeriod is additional seconds to wait for interactions after closing
	// of the poller.
	InteractionsCoolDownPeriod int `json:"interactions_cool_down_period"`
	// MaxRedirects is the maximum numbers of redirects to be followed.
	MaxRedirects int `json:"max_redirects"`
	// FollowRedirects enables following redirects for http request module
	FollowRedirects bool `json:"follow_redirects"`
	// FollowRedirects enables following redirects for http request module only on the same host
	FollowHostRedirects bool `json:"follow_host_redirects"`
	// OfflineHTTP is a flag that specific offline processing of http response
	// using same matchers/extractors from http protocol without the need
	// to send a new request, reading responses from a file.
	OfflineHTTP bool `json:"offline_http"`
	// Force HTTP2 requests
	ForceAttemptHTTP2 bool `json:"force_attempt_http_2"`
	// StatsJSON writes stats output in JSON format
	StatsJSON bool `json:"stats_json"`
	// Headless specifies whether to allow headless mode templates
	Headless bool `json:"headless"`
	// ShowBrowser specifies whether the show the browser in headless mode
	ShowBrowser bool `json:"show_browser"`
	// HeadlessOptionalArguments specifies optional arguments to pass to Chrome
	HeadlessOptionalArguments goflags.StringSlice `json:"headless_optional_arguments"`
	// DisableClustering disables clustering of templates
	DisableClustering bool `json:"disable_clustering"`
	// UseInstalledChrome skips chrome install and use local instance
	UseInstalledChrome bool `json:"use_installed_chrome"`
	// SystemResolvers enables override of nuclei's DNS client opting to use system resolver stack.
	SystemResolvers bool `json:"system_resolvers"`
	// ShowActions displays a list of all headless actions
	ShowActions bool `json:"show_actions"`
	// Deprecated: Enabled by default through clistats . Metrics enables display of metrics via an http endpoint
	Metrics bool `json:"metrics"`
	// Debug mode allows debugging request/responses for the engine
	Debug bool `json:"debug"`
	// DebugRequests mode allows debugging request for the engine
	DebugRequests bool `json:"debug_requests"`
	// DebugResponse mode allows debugging response for the engine
	DebugResponse bool `json:"debug_response"`
	// DisableHTTPProbe disables http probing feature of input normalization
	DisableHTTPProbe bool `json:"disable_http_probe"`
	// LeaveDefaultPorts skips normalization of default ports
	LeaveDefaultPorts bool `json:"leave_default_ports"`
	// AutomaticScan enables automatic tech based template execution
	AutomaticScan bool `json:"automatic_scan"`
	// Silent suppresses any extra text and only writes found URLs on screen.
	Silent bool `json:"silent"`
	// Validate validates the templates passed to nuclei.
	Validate bool `json:"validate"`
	// NoStrictSyntax disables strict syntax check on nuclei templates (allows custom key-value pairs).
	NoStrictSyntax bool `json:"no_strict_syntax"`
	// Verbose flag indicates whether to show verbose output or not
	Verbose        bool `json:"verbose"`
	VerboseVerbose bool `json:"verbose_verbose"`
	// ShowVarDump displays variable dump
	ShowVarDump bool `json:"show_var_dump"`
	// VarDumpLimit limits the number of characters displayed in var dump
	VarDumpLimit int `json:"var_dump_limit"`
	// No-Color disables the colored output.
	NoColor bool `json:"no_color"`
	// UpdateTemplates updates the templates installed at startup (also used by cloud to update datasources)
	UpdateTemplates bool `json:"update_templates"`
	// JSON writes json line output to files
	JSONL bool `json:"jsonl"`
	// JSONRequests writes requests/responses for matches in JSON output
	// Deprecated: use OmitRawRequests instead as of now JSONRequests(include raw requests) is always true
	JSONRequests bool `json:"json_requests"`
	// OmitRawRequests omits requests/responses for matches in JSON output
	OmitRawRequests bool `json:"omit_raw_requests"`
	// OmitTemplate omits encoded template from JSON output
	OmitTemplate bool `json:"omit_template"`
	// JSONExport is the file to export JSON output format to
	JSONExport string `json:"json_export"`
	// JSONLExport is the file to export JSONL output format to
	JSONLExport string `json:"jsonl_export"`
	// Redact redacts given keys in
	Redact goflags.StringSlice `json:"redact"`
	// EnableProgressBar enables progress bar
	EnableProgressBar bool `json:"enable_progress_bar"`
	// TemplateDisplay displays the template contents
	TemplateDisplay bool `json:"template_display"`
	// TemplateList lists available templates
	TemplateList bool `json:"template_list"`
	// TemplateList lists available tags
	TagList bool `json:"tag_list"`
	// HangMonitor enables nuclei hang monitoring
	HangMonitor bool `json:"hang_monitor"`
	// Stdin specifies whether stdin input was given to the process
	Stdin bool `json:"stdin"`
	// StopAtFirstMatch stops processing template at first full match (this may break chained requests)
	StopAtFirstMatch bool `json:"stop_at_first_match"`
	// Stream the input without sorting
	Stream bool `json:"stream"`
	// NoMeta disables display of metadata for the matches
	NoMeta bool `json:"no_meta"`
	// Timestamp enables display of timestamp for the matcher
	Timestamp bool `json:"timestamp"`
	// Project is used to avoid sending same HTTP request multiple times
	Project bool `json:"project"`
	// NewTemplates only runs newly added templates from the repository
	NewTemplates bool `json:"new_templates"`
	// NewTemplatesWithVersion runs new templates added in specific version
	NewTemplatesWithVersion goflags.StringSlice `json:"new_templates_with_version"`
	// NoInteractsh disables use of interactsh server for interaction polling
	NoInteractsh bool `json:"no_interactsh"`
	// EnvironmentVariables enables support for environment variables
	EnvironmentVariables bool `json:"environment_variables"`
	// MatcherStatus displays optional status for the failed matches as well
	MatcherStatus bool `json:"matcher_status"`
	// ClientCertFile client certificate file (PEM-encoded) used for authenticating against scanned hosts
	ClientCertFile string `json:"client_cert_file"`
	// ClientKeyFile client key file (PEM-encoded) used for authenticating against scanned hosts
	ClientKeyFile string `json:"client_key_file"`
	// ClientCAFile client certificate authority file (PEM-encoded) used for authenticating against scanned hosts
	ClientCAFile string `json:"client_ca_file"`
	// Deprecated: Use ZTLS library
	ZTLS bool `json:"ztls"`
	// AllowLocalFileAccess allows local file access from templates payloads
	AllowLocalFileAccess bool `json:"allow_local_file_access"`
	// RestrictLocalNetworkAccess restricts local network access from templates requests
	RestrictLocalNetworkAccess bool `json:"restrict_local_network_access"`
	// ShowMatchLine enables display of match line number
	ShowMatchLine bool `json:"show_match_line"`
	// EnablePprof enables exposing pprof runtime information with a webserver.
	EnablePprof bool `json:"enable_pprof"`
	// StoreResponse stores received response to output directory
	StoreResponse bool `json:"store_response"`
	// StoreResponseDir stores received response to custom directory
	StoreResponseDir string `json:"store_response_dir"`
	// DisableRedirects disables following redirects for http request module
	DisableRedirects bool `json:"disable_redirects"`
	// SNI custom hostname
	SNI string `json:"sni"`
	// InputFileMode specifies the mode of input file (jsonl, burp, openapi, swagger, etc)
	InputFileMode string `json:"input_file_mode"`
	// DialerKeepAlive sets the keep alive duration for network requests.
	DialerKeepAlive time.Duration `json:"dialer_keep_alive"`
	// Interface to use for network scan
	Interface string `json:"interface"`
	// SourceIP sets custom source IP address for network requests
	SourceIP string `json:"source_ip"`
	// AttackType overrides template level attack-type configuration
	AttackType string `json:"attack_type"`
	// ResponseReadSize is the maximum size of response to read
	ResponseReadSize int `json:"response_read_size"`
	// ResponseSaveSize is the maximum size of response to save
	ResponseSaveSize int `json:"response_save_size"`
	// Health Check
	HealthCheck bool `json:"health_check"`
	// Time to wait between each input read operation before closing the stream
	InputReadTimeout time.Duration `json:"input_read_timeout"`
	// Disable stdin for input processing
	DisableStdin bool `json:"disable_stdin"`
	// IncludeConditions is the list of conditions templates should match
	IncludeConditions goflags.StringSlice `json:"include_conditions"`
	// Enable uncover engine
	Uncover bool `json:"uncover"`
	// Uncover search query
	UncoverQuery goflags.StringSlice `json:"uncover_query"`
	// Uncover search engine
	UncoverEngine goflags.StringSlice `json:"uncover_engine"`
	// Uncover search field
	UncoverField string `json:"uncover_field"`
	// Uncover search limit
	UncoverLimit int `json:"uncover_limit"`
	// Uncover search delay
	UncoverRateLimit int `json:"uncover_rate_limit"`
	// ScanAllIPs associated to a dns record
	ScanAllIPs bool `json:"scan_all_i_ps"`
	// IPVersion to scan (4,6)
	IPVersion goflags.StringSlice `json:"ip_version"`
	// PublicTemplateDisableDownload disables downloading templates from the nuclei-templates public repository
	PublicTemplateDisableDownload bool `json:"public_template_disable_download"`
	// GitHub token used to clone/pull from private repos for custom templates
	GitHubToken string `json:"git_hub_token"`
	// GitHubTemplateRepo is the list of custom public/private templates GitHub repos
	GitHubTemplateRepo []string `json:"git_hub_template_repo"`
	// GitHubTemplateDisableDownload disables downloading templates from custom GitHub repositories
	GitHubTemplateDisableDownload bool `json:"git_hub_template_disable_download"`
	// GitLabServerURL is the gitlab server to use for custom templates
	GitLabServerURL string `json:"git_lab_server_url"`
	// GitLabToken used to clone/pull from private repos for custom templates
	GitLabToken string `json:"git_lab_token"`
	// GitLabTemplateRepositoryIDs is the comma-separated list of custom gitlab repositories IDs
	GitLabTemplateRepositoryIDs []int `json:"git_lab_template_repository_i_ds"`
	// GitLabTemplateDisableDownload disables downloading templates from custom GitLab repositories
	GitLabTemplateDisableDownload bool `json:"git_lab_template_disable_download"`
	// AWS access key for downloading templates from S3 bucket
	AwsAccessKey string `json:"aws_access_key"`
	// AWS secret key for downloading templates from S3 bucket
	AwsSecretKey string `json:"aws_secret_key"`
	// AWS bucket name for downloading templates from S3 bucket
	AwsBucketName string `json:"aws_bucket_name"`
	// AWS Region name where AWS S3 bucket is located
	AwsRegion string `json:"aws_region"`
	// AwsTemplateDisableDownload disables downloading templates from AWS S3 buckets
	AwsTemplateDisableDownload bool `json:"aws_template_disable_download"`
	// AzureContainerName for downloading templates from Azure Blob Storage. Example: templates
	AzureContainerName string `json:"azure_container_name"`
	// AzureTenantID for downloading templates from Azure Blob Storage. Example: 00000000-0000-0000-0000-000000000000
	AzureTenantID string `json:"azure_tenant_id"`
	// AzureClientID for downloading templates from Azure Blob Storage. Example: 00000000-0000-0000-0000-000000000000
	AzureClientID string `json:"azure_client_id"`
	// AzureClientSecret for downloading templates from Azure Blob Storage. Example: 00000000-0000-0000-0000-000000000000
	AzureClientSecret string `json:"azure_client_secret"`
	// AzureServiceURL for downloading templates from Azure Blob Storage. Example: https://XXXXXXXXXX.blob.core.windows.net/
	AzureServiceURL string `json:"azure_service_url"`
	// AzureTemplateDisableDownload disables downloading templates from Azure Blob Storage
	AzureTemplateDisableDownload bool `json:"azure_template_disable_download"`
	// Scan Strategy (auto,hosts-spray,templates-spray)
	ScanStrategy string `json:"scan_strategy"`
	// Fuzzing Type overrides template level fuzzing-type configuration
	FuzzingType string `json:"fuzzing_type"`
	// Fuzzing Mode overrides template level fuzzing-mode configuration
	FuzzingMode string `json:"fuzzing_mode"`
	// TlsImpersonate enables TLS impersonation
	TlsImpersonate bool `json:"tls_impersonate"`
	// DisplayFuzzPoints enables display of fuzz points for fuzzing
	DisplayFuzzPoints bool `json:"display_fuzz_points"`
	// FuzzAggressionLevel is the level of fuzzing aggression (low, medium, high.)
	FuzzAggressionLevel string `json:"fuzz_aggression_level"`
	// FuzzParamFrequency is the frequency of fuzzing parameters
	FuzzParamFrequency int `json:"fuzz_param_frequency"`
	// CodeTemplateSignaturePublicKey is the custom public key used to verify the template signature (algorithm is automatically inferred from the length)
	CodeTemplateSignaturePublicKey string `json:"code_template_signature_public_key"`
	// CodeTemplateSignatureAlgorithm specifies the sign algorithm (rsa, ecdsa)
	CodeTemplateSignatureAlgorithm string `json:"code_template_signature_algorithm"`
	// SignTemplates enables signing of templates
	SignTemplates bool `json:"sign_templates"`
	// EnableCodeTemplates enables code templates
	EnableCodeTemplates bool `json:"enable_code_templates"`
	// DisableUnsignedTemplates disables processing of unsigned templates
	DisableUnsignedTemplates bool `json:"disable_unsigned_templates"`
	// EnableSelfContainedTemplates enables processing of self-contained templates
	EnableSelfContainedTemplates bool `json:"enable_self_contained_templates"`
	// EnableGlobalMatchersTemplates enables processing of global-matchers templates
	EnableGlobalMatchersTemplates bool `json:"enable_global_matchers_templates"`
	// EnableFileTemplates enables file templates
	EnableFileTemplates bool `json:"enable_file_templates"`
	// Disables cloud upload
	EnableCloudUpload bool `json:"enable_cloud_upload"`
	// ScanID is the scan ID to use for cloud upload
	ScanID string `json:"scan_id"`
	// ScanName is the name of the scan to be uploaded
	ScanName string `json:"scan_name"`
	// ScanUploadFile is the jsonl file to upload scan results to cloud
	ScanUploadFile string `json:"scan_upload_file"`
	// TeamID is the team ID to use for cloud upload
	TeamID string `json:"team_id"`
	// JsConcurrency is the number of concurrent js routines to run
	JsConcurrency int `json:"js_concurrency"`
	// SecretsFile is file containing secrets for nuclei
	SecretsFile goflags.StringSlice `json:"secrets_file"`
	// PreFetchSecrets pre-fetches the secrets from the auth provider
	PreFetchSecrets bool `json:"pre_fetch_secrets"`
	// FormatUseRequiredOnly only uses required fields when generating requests
	FormatUseRequiredOnly bool `json:"format_use_required_only"`
	// SkipFormatValidation is used to skip format validation
	SkipFormatValidation bool `json:"skip_format_validation"`
	// PayloadConcurrency is the number of concurrent payloads to run per template
	PayloadConcurrency int `json:"payload_concurrency"`
	// ProbeConcurrency is the number of concurrent http probes to run with httpx
	ProbeConcurrency int `json:"probe_concurrency"`
	// Dast only runs DAST templates
	DAST bool `json:"dast"`
	// HttpApiEndpoint is the experimental http api endpoint
	HttpApiEndpoint string `json:"http_api_endpoint"`
	// ListTemplateProfiles lists all available template profiles
	ListTemplateProfiles bool `json:"list_template_profiles"`
	// LoadHelperFileFunction is a function that will be used to execute LoadHelperFile.
	// If none is provided, then the default implementation will be used.
	LoadHelperFileFunction LoadHelperFileFunction `json:"-"`
	// timeouts contains various types of timeouts used in nuclei
	// these timeouts are derived from dial-timeout (-timeout) with known multipliers
	// This is internally managed and does not need to be set by user by explicitly setting
	// this overrides the default/derived one
	timeouts *Timeouts `json:"timeouts"`
}

// SetTimeouts sets the timeout variants to use for the executor
func (opts *Options) SetTimeouts(t *Timeouts) {
	opts.timeouts = t
}

// GetTimeouts returns the timeout variants to use for the executor
func (eo *Options) GetTimeouts() *Timeouts {
	if eo.timeouts != nil {
		// redundant but apply to avoid any potential issues
		eo.timeouts.ApplyDefaults()
		return eo.timeouts
	}
	// set timeout variant value
	eo.timeouts = NewTimeoutVariant(eo.Timeout)
	eo.timeouts.ApplyDefaults()
	return eo.timeouts
}

// Timeouts is a struct that contains all the timeout variants for nuclei
// dialer timeout is used to derive other timeouts
type Timeouts struct {
	// DialTimeout for fastdialer (default 10s)
	DialTimeout time.Duration
	// Tcp(Network Protocol) Read From Connection Timeout (default 5s)
	TcpReadTimeout time.Duration
	// Http Response Header Timeout (default 10s)
	// this timeout prevents infinite hangs started by server if any
	// this is temporarily overridden when using @timeout request annotation
	HttpResponseHeaderTimeout time.Duration
	// HttpTimeout for http client (default -> 3 x dial-timeout = 30s)
	HttpTimeout time.Duration
	// JsCompilerExec timeout/deadline (default -> 2 x dial-timeout = 20s)
	JsCompilerExecutionTimeout time.Duration
	// CodeExecutionTimeout for code execution (default -> 3 x dial-timeout = 30s)
	CodeExecutionTimeout time.Duration
}

// NewTimeoutVariant creates a new timeout variant with the given dial timeout in seconds
func NewTimeoutVariant(dialTimeoutSec int) *Timeouts {
	tv := &Timeouts{
		DialTimeout: time.Duration(dialTimeoutSec) * time.Second,
	}
	tv.ApplyDefaults()
	return tv
}

// ApplyDefaults applies default values to timeout variants when missing
func (tv *Timeouts) ApplyDefaults() {
	if tv.DialTimeout == 0 {
		tv.DialTimeout = 10 * time.Second
	}
	if tv.TcpReadTimeout == 0 {
		tv.TcpReadTimeout = 5 * time.Second
	}
	if tv.HttpResponseHeaderTimeout == 0 {
		tv.HttpResponseHeaderTimeout = 10 * time.Second
	}
	if tv.HttpTimeout == 0 {
		tv.HttpTimeout = 3 * tv.DialTimeout
	}
	if tv.JsCompilerExecutionTimeout == 0 {
		tv.JsCompilerExecutionTimeout = 2 * tv.DialTimeout
	}
	if tv.CodeExecutionTimeout == 0 {
		tv.CodeExecutionTimeout = 3 * tv.DialTimeout
	}
}

// ShouldLoadResume resume file
func (options *Options) ShouldLoadResume() bool {
	return options.Resume != "" && fileutil.FileExists(options.Resume)
}

// ShouldSaveResume file
func (options *Options) ShouldSaveResume() bool {
	return true
}

// ShouldFollowHTTPRedirects determines if http redirects should be followed
func (options *Options) ShouldFollowHTTPRedirects() bool {
	return options.FollowRedirects || options.FollowHostRedirects
}

// HasClientCertificates determines if any client certificate was specified
func (options *Options) HasClientCertificates() bool {
	return options.ClientCertFile != "" || options.ClientCAFile != "" || options.ClientKeyFile != ""
}

// DefaultOptions returns default options for nuclei
func DefaultOptions() *Options {
	return &Options{
		RateLimit:               150,
		RateLimitDuration:       time.Second,
		BulkSize:                25,
		TemplateThreads:         25,
		HeadlessBulkSize:        10,
		PayloadConcurrency:      25,
		HeadlessTemplateThreads: 10,
		ProbeConcurrency:        50,
		Timeout:                 5,
		Retries:                 1,
		MaxHostError:            30,
		ResponseReadSize:        10 * unitutils.Mega,
		ResponseSaveSize:        unitutils.Mega,
	}
}

func (options *Options) ShouldUseHostError() bool {
	return options.MaxHostError > 0 && !options.NoHostErrors
}

func (options *Options) ParseHeadlessOptionalArguments() map[string]string {
	optionalArguments := make(map[string]string)
	for _, v := range options.HeadlessOptionalArguments {
		if argParts := strings.SplitN(v, "=", 2); len(argParts) >= 2 {
			key := strings.TrimSpace(argParts[0])
			value := strings.TrimSpace(argParts[1])
			if key != "" && value != "" {
				optionalArguments[key] = value
			}
		}
	}
	return optionalArguments
}

// LoadHelperFile loads a helper file needed for the template.
//
// If LoadHelperFileFunction is set, then that function will be used.
// Otherwise, the default implementation will be used, which respects the sandbox rules and only loads files from allowed directories.
func (options *Options) LoadHelperFile(helperFile, templatePath string, catalog catalog.Catalog) (io.ReadCloser, error) {
	if options.LoadHelperFileFunction != nil {
		return options.LoadHelperFileFunction(helperFile, templatePath, catalog)
	}
	return options.defaultLoadHelperFile(helperFile, templatePath, catalog)
}

// defaultLoadHelperFile loads a helper file needed for the template
// this respects the sandbox rules and only loads files from
// allowed directories
func (options *Options) defaultLoadHelperFile(helperFile, templatePath string, catalog catalog.Catalog) (io.ReadCloser, error) {
	if !options.AllowLocalFileAccess {
		// if global file access is disabled try loading with restrictions
		absPath, err := options.GetValidAbsPath(helperFile, templatePath)
		if err != nil {
			return nil, err
		}
		helperFile = absPath
	}
	f, err := os.Open(helperFile)
	if err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("could not open file %v", helperFile)
	}
	return f, nil
}

// GetValidAbsPath returns absolute path of helper file if it is allowed to be loaded
// this respects the sandbox rules and only loads files from allowed directories
func (o *Options) GetValidAbsPath(helperFilePath, templatePath string) (string, error) {
	// Conditions to allow helper file
	// 1. If helper file is present in nuclei-templates directory
	// 2. If helper file and template file are in same directory given that its not root directory

	// resolve and clean helper file path
	// ResolveNClean uses a custom base path instead of CWD
	resolvedPath, err := fileutil.ResolveNClean(helperFilePath, config.DefaultConfig.GetTemplateDir())
	if err == nil {
		// As per rule 1, if helper file is present in nuclei-templates directory, allow it
		if strings.HasPrefix(resolvedPath, config.DefaultConfig.GetTemplateDir()) {
			return resolvedPath, nil
		}
	}

	// CleanPath resolves using CWD and cleans the path
	helperFilePath, err = fileutil.CleanPath(helperFilePath)
	if err != nil {
		return "", errorutil.NewWithErr(err).Msgf("could not clean helper file path %v", helperFilePath)
	}

	templatePath, err = fileutil.CleanPath(templatePath)
	if err != nil {
		return "", errorutil.NewWithErr(err).Msgf("could not clean template path %v", templatePath)
	}

	// As per rule 2, if template and helper file exist in same directory or helper file existed in any child dir of template dir
	// and both of them are present in user home directory, allow it
	// Review: should we keep this rule ? add extra option to disable this ?
	if isHomeDir(helperFilePath) && isHomeDir(templatePath) && strings.HasPrefix(filepath.Dir(helperFilePath), filepath.Dir(templatePath)) {
		return helperFilePath, nil
	}

	// all other cases are denied
	return "", errorutil.New("access to helper file %v denied", helperFilePath)
}

// isHomeDir checks if given is home directory
func isHomeDir(path string) bool {
	homeDir := folderutil.HomeDirOrDefault("")
	return strings.HasPrefix(path, homeDir)
}
