// Package version holds build information set with -ldflags at release time.
package version

var (
	// Version is the release tag, for example "v0.3.1". "dev" for local builds.
	Version = "dev"
	// Repo is the GitHub repository that self-update downloads from.
	Repo = "anmaksy/ab-win"
)
