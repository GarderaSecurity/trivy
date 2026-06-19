package pdm

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_pdmLibraryAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   bool
	}{
		{
			name:      "happy path",
			inputFile: "testdata/happy/pdm.lock",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Pdm,
						FilePath: "testdata/happy/pdm.lock",
						Packages: types.Packages{
							{
								ID:      "flask@1.0.3",
								Name:    "flask",
								Version: "1.0.3",
								DependsOn: []string{
									"click@8.1.8",
									"itsdangerous@2.2.0",
									"jinja2@3.1.5",
								},
							},
							{
								ID:      "click@8.1.8",
								Name:    "click",
								Version: "8.1.8",
							},
							{
								ID:        "jinja2@3.1.5",
								Name:      "jinja2",
								Version:   "3.1.5",
								DependsOn: []string{"markupsafe@3.0.2"},
							},
							{
								ID:      "markupsafe@3.0.2",
								Name:    "markupsafe",
								Version: "3.0.2",
							},
							{
								ID:      "itsdangerous@2.2.0",
								Name:    "itsdangerous",
								Version: "2.2.0",
							},
							{
								ID:      "pytest@5.4.3",
								Name:    "pytest",
								Version: "5.4.3",
								Dev:     true,
								DependsOn: []string{
									"colorama@0.4.6",
									"jinja2@3.1.5",
									"packaging@24.2",
								},
							},
							{
								ID:      "packaging@24.2",
								Name:    "packaging",
								Version: "24.2",
							},
							{
								ID:      "colorama@0.4.6",
								Name:    "colorama",
								Version: "0.4.6",
							},
							{
								ID:      "attrs@25.1.0",
								Name:    "attrs",
								Version: "25.1.0",
								Dev:     true,
							},
						},
					},
				},
			},
		},
		{
			name:      "broken lockfile",
			inputFile: "testdata/sad/pdm.lock",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			a := pdmLibraryAnalyzer{}
			got, err := a.Analyze(t.Context(), analyzer.AnalysisInput{
				FilePath: tt.inputFile,
				Content:  f,
			})

			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_pdmLibraryAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{name: "match", filePath: "project/pdm.lock", want: true},
		{name: "root", filePath: "pdm.lock", want: true},
		{name: "wrong file", filePath: "poetry.lock", want: false},
		{name: "similar name", filePath: "notpdm.lock", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := pdmLibraryAnalyzer{}
			assert.Equal(t, tt.want, a.Required(tt.filePath, nil))
		})
	}
}
