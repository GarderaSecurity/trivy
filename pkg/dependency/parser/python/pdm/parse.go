package pdm

import (
	"context"
	"slices"
	"strings"
	"unicode"

	"github.com/BurntSushi/toml"
	"golang.org/x/xerrors"

	version "github.com/aquasecurity/go-pep440-version"
	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/python"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

// defaultGroup is PDM's group name for production dependencies.
// Packages outside this group are dev/optional.
// cf. https://pdm-project.org/en/latest/usage/dependency/
const defaultGroup = "default"

type Lockfile struct {
	Packages []Package `toml:"package"`
}

type Package struct {
	Name         string   `toml:"name"`
	Version      string   `toml:"version"`
	Groups       []string `toml:"groups"`
	Dependencies []string `toml:"dependencies"`
}

type Parser struct {
	logger *log.Logger
}

func NewParser() *Parser {
	return &Parser{logger: log.WithPrefix("pdm")}
}

func (p *Parser) Parse(_ context.Context, r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	var lockfile Lockfile
	if _, err := toml.NewDecoder(r).Decode(&lockfile); err != nil {
		return nil, nil, xerrors.Errorf("failed to decode pdm.lock: %w", err)
	}

	pkgVersions := parseVersions(lockfile)

	var pkgs []ftypes.Package
	var deps []ftypes.Dependency
	for _, pkg := range lockfile.Packages {
		name := python.NormalizePkgName(pkg.Name, true)
		pkgID := packageID(name, pkg.Version)

		pkgs = append(pkgs, ftypes.Package{
			ID:      pkgID,
			Name:    name,
			Version: pkg.Version,
			Dev:     isDev(pkg.Groups),
		})

		dependsOn := p.parseDependencies(pkg.Dependencies, pkgVersions)
		if len(dependsOn) > 0 {
			deps = append(deps, ftypes.Dependency{
				ID:        pkgID,
				DependsOn: dependsOn,
			})
		}
	}
	return pkgs, deps, nil
}

// isDev reports whether a package is dev-only (no membership in PDM's default group).
func isDev(groups []string) bool {
	return len(groups) > 0 && !slices.Contains(groups, defaultGroup)
}

// parseVersions indexes production package versions by normalized name, so
// dependency PEP 508 version ranges can be resolved to concrete versions.
func parseVersions(lockfile Lockfile) map[string][]string {
	pkgVersions := make(map[string][]string)
	for _, pkg := range lockfile.Packages {
		if isDev(pkg.Groups) {
			continue
		}
		name := python.NormalizePkgName(pkg.Name, true)
		pkgVersions[name] = append(pkgVersions[name], pkg.Version)
	}
	return pkgVersions
}

func (p *Parser) parseDependencies(specs []string, pkgVersions map[string][]string) []string {
	var dependsOn []string
	for _, spec := range specs {
		name, constraint := splitPEP508(spec)
		if name == "" {
			continue
		}
		name = python.NormalizePkgName(name, true)

		dep, err := resolveDependency(name, constraint, pkgVersions)
		if err != nil {
			p.logger.Debug("Failed to resolve pdm dependency",
				log.String("spec", spec), log.Err(err))
			continue
		}
		if dep != "" {
			dependsOn = append(dependsOn, dep)
		}
	}
	slices.Sort(dependsOn)
	return dependsOn
}

func resolveDependency(name, constraint string, pkgVersions map[string][]string) (string, error) {
	vers, ok := pkgVersions[name]
	if !ok {
		return "", xerrors.Errorf("no version found for %q", name)
	}
	for _, ver := range vers {
		matched, err := matchVersion(ver, constraint)
		if err != nil {
			return "", xerrors.Errorf("failed to match version for %s: %w", name, err)
		}
		if matched {
			return packageID(name, ver), nil
		}
	}
	return "", xerrors.Errorf("no matched version found for %q", name)
}

func matchVersion(currentVersion, constraint string) (bool, error) {
	v, err := version.Parse(currentVersion)
	if err != nil {
		return false, xerrors.Errorf("python version error (%s): %s", currentVersion, err)
	}
	if constraint == "" {
		return true, nil
	}
	c, err := version.NewSpecifiers(constraint, version.WithPreRelease(true))
	if err != nil {
		return false, xerrors.Errorf("python constraint error (%s): %s", constraint, err)
	}
	return c.Check(v), nil
}

// splitPEP508 extracts the package name and version constraint from a PEP 508
// dependency spec, stripping extras and environment markers.
// e.g. `requests[socks]>=2.0; python_version >= "3.7"` -> ("requests", ">=2.0")
func splitPEP508(spec string) (string, string) {
	if i := strings.Index(spec, ";"); i >= 0 {
		spec = spec[:i]
	}
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return "", ""
	}

	name, rest := spec, ""
	for i, r := range spec {
		if !isNameChar(r) {
			name, rest = spec[:i], spec[i:]
			break
		}
	}

	rest = strings.TrimSpace(rest)
	if strings.HasPrefix(rest, "[") {
		if end := strings.Index(rest, "]"); end >= 0 {
			rest = strings.TrimSpace(rest[end+1:])
		}
	}
	if strings.HasPrefix(rest, "(") && strings.HasSuffix(rest, ")") {
		rest = strings.TrimSpace(rest[1 : len(rest)-1])
	}

	return name, rest
}

func isNameChar(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '_' || r == '-'
}

func packageID(name, ver string) string {
	return dependency.ID(ftypes.Pdm, name, ver)
}
