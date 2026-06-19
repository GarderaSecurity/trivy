package pdm

import (
	"context"
	"os"
	"path/filepath"
	"slices"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/python/pdm"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&pdmLibraryAnalyzer{})
}

const version = 1

var requiredFiles = []string{types.PdmLock}

type pdmLibraryAnalyzer struct{}

func (a pdmLibraryAnalyzer) Analyze(ctx context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	res, err := language.Analyze(ctx, types.Pdm, input.FilePath, input.Content, pdm.NewParser())
	if err != nil {
		return nil, xerrors.Errorf("unable to parse pdm.lock: %w", err)
	}
	return res, nil
}

func (a pdmLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return slices.Contains(requiredFiles, fileName)
}

func (a pdmLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypePdm
}

func (a pdmLibraryAnalyzer) Version() int {
	return version
}
