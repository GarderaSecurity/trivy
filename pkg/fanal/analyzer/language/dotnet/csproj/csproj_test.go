package csproj

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_csprojAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name:      "project file without a lock file",
			inputFile: "testdata/plain/SecDev.Api.csproj",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Csproj,
						FilePath: "testdata/plain/SecDev.Api.csproj",
						Packages: types.Packages{
							{
								ID:      "Newtonsoft.Json@12.0.3",
								Name:    "Newtonsoft.Json",
								Version: "12.0.3",
							},
						},
					},
				},
			},
		},
		{
			name:      "project file next to packages.lock.json is left to the lock file",
			inputFile: "testdata/with-lock/SecDev.Api.csproj",
			want:      nil,
		},
		{
			name:      "invalid",
			inputFile: "testdata/invalid.csproj",
			wantErr:   "*.csproj dependencies analysis error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			a := csprojAnalyzer{}
			got, err := a.Analyze(t.Context(), analyzer.AnalysisInput{
				Dir:      ".",
				FilePath: tt.inputFile,
				Content:  f,
			})

			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_csprojAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{name: "csproj", filePath: "src/Api/Api.csproj", want: true},
		{name: "vbproj", filePath: "src/Legacy/Legacy.vbproj", want: true},
		{name: "fsproj", filePath: "src/Core/Core.fsproj", want: true},
		{name: "upper case", filePath: "src/Api/Api.CSPROJ", want: true},
		{name: "props", filePath: "Directory.Packages.props", want: false},
		{name: "sln", filePath: "Api.sln", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := csprojAnalyzer{}
			assert.Equal(t, tt.want, a.Required(tt.filePath, nil))
		})
	}
}
