// Package productinfo exposes only ANDEIVA's own product build identity.
package productinfo

import "regexp"

// Version is set by the reviewed package build. It is not read from requests or
// the environment, and an ordinary development build has no installed version.
var Version string

type Info struct {
	Product      string `json:"product"`
	Version      string `json:"version,omitempty"`
	Channel      string `json:"channel"`
	UpdateStatus string `json:"update_status"`
}

var previewVersion = regexp.MustCompile(`^0\.1\.0~alpha[1-9][0-9]*$`)

func Current() Info { return fromVersion(Version) }

// Valid accepts only this public product contract, not arbitrary build metadata.
func Valid(info Info) bool { return info == fromVersion(info.Version) }

func fromVersion(version string) Info {
	info := Info{Product: "ANDEIVA Security Gateway", Channel: "development", UpdateStatus: "unavailable"}
	if len(version) <= 64 && previewVersion.MatchString(version) {
		info.Version, info.Channel = version, "experimental"
	}
	return info
}
