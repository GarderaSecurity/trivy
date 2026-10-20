// Package csproj parses the PackageReference items of an SDK-style .NET
// project file (*.csproj, *.vbproj, *.fsproj).
//
// A project file declares what the project asked for, not what NuGet
// resolved: it holds direct dependencies only, and a version may be a range,
// a wildcard or an MSBuild property. Only entries with one exact version are
// reported, so the result is a lower bound on the installed packages. A
// packages.lock.json or *.deps.json next to the project is the complete
// picture, and is preferred when present.
package csproj

import (
	"context"
	"encoding/xml"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/utils"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

// https://learn.microsoft.com/en-us/nuget/consume-packages/package-references-in-project-files
type packageReference struct {
	Include         string `xml:"Include,attr"`
	Update          string `xml:"Update,attr"`
	VersionAttr     string `xml:"Version,attr"`
	VersionOverride string `xml:"VersionOverride,attr"` // central package management
	VersionElement  string `xml:"Version"`
}

type itemGroup struct {
	PackageReferences []packageReference `xml:"PackageReference"`
}

type project struct {
	XMLName    xml.Name    `xml:"Project"`
	ItemGroups []itemGroup `xml:"ItemGroup"`
}

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(_ context.Context, r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	var proj project
	if err := xml.NewDecoder(r).Decode(&proj); err != nil {
		return nil, nil, xerrors.Errorf("failed to decode '*.csproj' file: %w", err)
	}

	var pkgs []ftypes.Package
	for _, group := range proj.ItemGroups {
		for _, ref := range group.PackageReferences {
			if pkg, ok := ref.toPackage(); ok {
				pkgs = append(pkgs, pkg)
			}
		}
	}
	return utils.UniquePackages(pkgs), nil, nil
}

func (ref packageReference) toPackage() (ftypes.Package, bool) {
	// Update is the legacy spelling, so Include wins when both are set.
	name := strings.TrimSpace(ref.Include)
	if name == "" {
		name = strings.TrimSpace(ref.Update)
	}
	version, ok := exactVersion(ref.VersionAttr, ref.VersionElement, ref.VersionOverride)
	if name == "" || !ok || isProperty(name) {
		return ftypes.Package{}, false
	}
	return ftypes.Package{
		ID:      dependency.ID(ftypes.NuGet, name, version),
		Name:    name,
		Version: version,
	}, true
}

// exactVersion returns the one version a reference pins, from the first of
// the candidates that is set. A wildcard, a range or an MSBuild property is
// not a version NuGet has resolved yet, so those give no version.
func exactVersion(candidates ...string) (string, bool) {
	var raw string
	for _, c := range candidates {
		if raw = strings.TrimSpace(c); raw != "" {
			break
		}
	}
	if raw == "" || isProperty(raw) || strings.Contains(raw, "*") {
		return "", false
	}
	// "[1.2.3]" is NuGet's range syntax for exactly 1.2.3.
	if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") && !strings.Contains(raw, ",") {
		raw = strings.TrimSpace(raw[1 : len(raw)-1])
		if raw == "" {
			return "", false
		}
	}
	if strings.ContainsAny(raw, "[](),") {
		return "", false
	}
	return raw, true
}

func isProperty(s string) bool {
	return strings.Contains(s, "$(")
}
