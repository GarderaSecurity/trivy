package csproj_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/nuget/csproj"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      []ftypes.Package
		wantErr   string
	}{
		{
			name:      "AttributeVersion",
			inputFile: "testdata/SecDev.Api.csproj",
			want: []ftypes.Package{
				{Name: "Newtonsoft.Json", Version: "12.0.3", ID: "Newtonsoft.Json@12.0.3"},
			},
		},
		{
			name:      "ElementVersionUpdateAndWhitespace",
			inputFile: "testdata/element_versions.csproj",
			want: []ftypes.Package{
				{Name: "PackageOne", Version: "6.2.3", ID: "PackageOne@6.2.3"},
				{Name: "PackageThree", Version: "2.4.1", ID: "PackageThree@2.4.1"},
				{Name: "PackageTwo", Version: "6.0.0", ID: "PackageTwo@6.0.0"},
			},
		},
		{
			name:      "OnlyExactVersionsAreReported",
			inputFile: "testdata/skipped_versions.csproj",
			want: []ftypes.Package{
				{Name: "ExactPin", Version: "12.0.3", ID: "ExactPin@12.0.3"},
				{Name: "Overridden", Version: "2.0.0", ID: "Overridden@2.0.0"},
				{Name: "Prerelease", Version: "1.0.0-beta.1", ID: "Prerelease@1.0.0-beta.1"},
			},
		},
		{
			name:      "NoItemGroup",
			inputFile: "testdata/no_item_group.csproj",
			want:      []ftypes.Package(nil),
		},
		{
			name:      "NoProject",
			inputFile: "testdata/no_project.csproj",
			wantErr:   "failed to decode '*.csproj' file",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)

			got, _, err := csproj.NewParser().Parse(t.Context(), f)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
