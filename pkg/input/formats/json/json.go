package json

import (
	"encoding/json"
	"io"
	"os"

	"github.com/iami317/nuclei/v3/pkg/input/formats"
	"github.com/iami317/nuclei/v3/pkg/input/types"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
)

// JSONFormat is a JSON format parser for nuclei
// input HTTP requests
type JSONFormat struct {
	opts formats.InputFormatOptions
}

// New creates a new JSON format parser
func New() *JSONFormat {
	return &JSONFormat{}
}

var _ formats.Format = &JSONFormat{}

// proxifyRequest is a request for proxify
type proxifyRequest struct {
	URL     string `json:"url"`
	Request struct {
		Header   map[string]string `json:"header"`
		Body     string            `json:"body"`
		Raw      string            `json:"raw"`
		Endpoint string            `json:"endpoint"`
	} `json:"request"`
}

// Name returns the name of the format
func (j *JSONFormat) Name() string {
	return "jsonl"
}

func (j *JSONFormat) SetOptions(options formats.InputFormatOptions) {
	j.opts = options
}

// Parse parses the input and calls the provided callback
// function for each RawRequest it discovers.
func (j *JSONFormat) Parse(input string, resultsCb formats.ParseReqRespCallback) error {
	file, err := os.Open(input)
	if err != nil {
		return errors.Wrap(err, "could not open json file")
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	for {
		var request proxifyRequest
		err := decoder.Decode(&request)
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.Wrap(err, "could not decode json file")
		}

		if request.URL == "" && request.Request.Endpoint != "" {
			request.URL = request.Request.Endpoint
		}
		rawRequest, err := types.ParseRawRequestWithURL(request.Request.Raw, request.URL)
		if err != nil {
			gologger.Warning().Msgf("jsonl: Could not parse raw request %s: %s\n", request.URL, err)
			continue
		}
		resultsCb(rawRequest)
	}
	return nil
}
