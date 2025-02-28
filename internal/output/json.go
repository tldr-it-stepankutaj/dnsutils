package output

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/tldr-it-stepankutaj/dnsutils/internal/models"
)

// JSON handles JSON output
type JSON struct{}

// NewJSON creates a new JSON formatter
func NewJSON() *JSON {
	return &JSON{}
}

// SaveResultsToJSON saves scan results to a JSON file
func (j *JSON) SaveResultsToJSON(results *models.Results, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("error creating file: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	err = encoder.Encode(results)
	if err != nil {
		return fmt.Errorf("error encoding JSON: %v", err)
	}

	return nil
}
