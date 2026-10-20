package csproj

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/nuget/csproj"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&csprojAnalyzer{})
}

const (
	version  = 1
	lockFile = "packages.lock.json"
)

// SDK-style project files that hold PackageReference items.
var projectSuffixes = []string{".csproj", ".vbproj", ".fsproj"}

// csprojAnalyzer reports the direct, exactly pinned packages a .NET project
// file declares. It is a fallback for projects without a lock file: when
// packages.lock.json sits next to the project, that file is complete and
// this analyzer stands down so the packages are not reported twice.
type csprojAnalyzer struct{}

func (a csprojAnalyzer) Analyze(ctx context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	if hasLockFile(input.Dir, input.FilePath) {
		return nil, nil
	}
	res, err := language.Analyze(ctx, types.Csproj, input.FilePath, input.Content, csproj.NewParser())
	if err != nil {
		return nil, xerrors.Errorf("*.csproj dependencies analysis error: %w", err)
	}
	return res, nil
}

func hasLockFile(dir, filePath string) bool {
	_, err := os.Stat(filepath.Join(dir, filepath.Dir(filePath), lockFile))
	return err == nil
}

func (a csprojAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	lower := strings.ToLower(filePath)
	for _, suffix := range projectSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

func (a csprojAnalyzer) Type() analyzer.Type {
	return analyzer.TypeCsproj
}

func (a csprojAnalyzer) Version() int {
	return version
}
