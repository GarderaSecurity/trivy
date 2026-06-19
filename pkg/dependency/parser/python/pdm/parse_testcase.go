package pdm

import ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"

var (
	// Single-package lockfile with no dependencies.
	pdmNormal = []ftypes.Package{
		{ID: "aiocache@0.12.3", Name: "aiocache", Version: "0.12.3"},
	}

	// Hand-crafted lockfile covering: default vs non-default groups,
	// multi-group prod packages (default+tests), PEP 508 deps with extras
	// (Jinja2[async]>=2.0) and environment markers (colorama; sys_platform == "win32"),
	// and capital-case name normalization (Click, Jinja2, MarkupSafe).
	pdmFlask = []ftypes.Package{
		{ID: "flask@1.0.3", Name: "flask", Version: "1.0.3"},
		{ID: "click@8.1.8", Name: "click", Version: "8.1.8"},
		{ID: "jinja2@3.1.5", Name: "jinja2", Version: "3.1.5"},
		{ID: "markupsafe@3.0.2", Name: "markupsafe", Version: "3.0.2"},
		{ID: "itsdangerous@2.2.0", Name: "itsdangerous", Version: "2.2.0"},
		{ID: "pytest@5.4.3", Name: "pytest", Version: "5.4.3", Dev: true},
		{ID: "packaging@24.2", Name: "packaging", Version: "24.2"},
		{ID: "colorama@0.4.6", Name: "colorama", Version: "0.4.6"},
		{ID: "attrs@25.1.0", Name: "attrs", Version: "25.1.0", Dev: true},
	}

	pdmFlaskDeps = []ftypes.Dependency{
		{ID: "flask@1.0.3", DependsOn: []string{"click@8.1.8", "itsdangerous@2.2.0", "jinja2@3.1.5"}},
		{ID: "jinja2@3.1.5", DependsOn: []string{"markupsafe@3.0.2"}},
		{ID: "pytest@5.4.3", DependsOn: []string{"colorama@0.4.6", "jinja2@3.1.5", "packaging@24.2"}},
	}
)
