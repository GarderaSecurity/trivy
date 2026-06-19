package pdm

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestParser_Parse(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		wantPkgs []ftypes.Package
		wantDeps []ftypes.Dependency
		wantErr  assert.ErrorAssertionFunc
	}{
		{
			name:     "normal",
			file:     "testdata/pdm_normal.lock",
			wantPkgs: pdmNormal,
			wantErr:  assert.NoError,
		},
		{
			name:     "flask",
			file:     "testdata/pdm_flask.lock",
			wantPkgs: pdmFlask,
			wantDeps: pdmFlaskDeps,
			wantErr:  assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.file)
			require.NoError(t, err)
			defer f.Close()

			p := NewParser()
			gotPkgs, gotDeps, err := p.Parse(t.Context(), f)
			if !tt.wantErr(t, err, fmt.Sprintf("Parse(%v)", tt.file)) {
				return
			}
			assert.Equalf(t, tt.wantPkgs, gotPkgs, "Parse(%v)", tt.file)
			assert.Equalf(t, tt.wantDeps, gotDeps, "Parse(%v)", tt.file)
		})
	}
}

func TestSplitPEP508(t *testing.T) {
	tests := []struct {
		name           string
		spec           string
		wantName       string
		wantConstraint string
	}{
		{
			name:           "name only",
			spec:           "requests",
			wantName:       "requests",
			wantConstraint: "",
		},
		{
			name:           "simple version constraint",
			spec:           "requests>=2.0",
			wantName:       "requests",
			wantConstraint: ">=2.0",
		},
		{
			name:           "compound version constraint",
			spec:           "multidict<7.0,>=4.0",
			wantName:       "multidict",
			wantConstraint: "<7.0,>=4.0",
		},
		{
			name:           "with extras",
			spec:           "requests[socks]>=2.0",
			wantName:       "requests",
			wantConstraint: ">=2.0",
		},
		{
			name:           "with environment marker",
			spec:           `tomli; python_version < "3.11"`,
			wantName:       "tomli",
			wantConstraint: "",
		},
		{
			name:           "constraint and marker",
			spec:           `typing-extensions>=4.5; python_version < "3.13"`,
			wantName:       "typing-extensions",
			wantConstraint: ">=4.5",
		},
		{
			name:           "extras and marker",
			spec:           `Jinja2[async]>=2.0; python_version >= "3.7"`,
			wantName:       "Jinja2",
			wantConstraint: ">=2.0",
		},
		{
			name:           "parenthesized constraint",
			spec:           "requests (>=2.0)",
			wantName:       "requests",
			wantConstraint: ">=2.0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotName, gotConstraint := splitPEP508(tt.spec)
			assert.Equal(t, tt.wantName, gotName)
			assert.Equal(t, tt.wantConstraint, gotConstraint)
		})
	}
}

func TestIsDev(t *testing.T) {
	tests := []struct {
		name   string
		groups []string
		want   bool
	}{
		{name: "no groups", groups: nil, want: false},
		{name: "default only", groups: []string{"default"}, want: false},
		{name: "default + tests", groups: []string{"default", "tests"}, want: false},
		{name: "tests only", groups: []string{"tests"}, want: true},
		{name: "mypy only", groups: []string{"mypy"}, want: true},
		{name: "multiple non-default", groups: []string{"tests", "lint"}, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isDev(tt.groups))
		})
	}
}
