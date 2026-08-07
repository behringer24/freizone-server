package conformance

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "regenerate the committed vectors under testdata/")

// TestGenerateVectors rewrites testdata/ from Generate(). It is skipped by
// default: the committed vectors are what every consumer tests against, and
// regeneration mints fresh key material and fresh ciphertext, so it must be a
// deliberate act rather than a side effect of running the suite.
//
//	go test ./pkg/conformance -run TestGenerateVectors -update
//
// Expectations are authored in generator.go, not observed from any
// implementation, so regenerating does not launder a behaviour change into the
// vectors -- only the envelope bytes move.
func TestGenerateVectors(t *testing.T) {
	if !*update {
		t.Skip("pass -update to regenerate testdata vectors")
	}

	vectors, err := Generate()
	if err != nil {
		t.Fatalf("generating vectors: %v", err)
	}

	dir := "testdata"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("creating %s: %v", dir, err)
	}

	seen := make(map[string]bool, len(vectors))
	for _, v := range vectors {
		if seen[v.Name] {
			t.Fatalf("duplicate vector name %q", v.Name)
		}
		seen[v.Name] = true

		data, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			t.Fatalf("%s: marshalling: %v", v.Name, err)
		}
		path := filepath.Join(dir, v.Name+".json")
		if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
			t.Fatalf("%s: writing: %v", v.Name, err)
		}
		t.Logf("wrote %s (%d steps)", path, len(v.Steps))
	}
}
