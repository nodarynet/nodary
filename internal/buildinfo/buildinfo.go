// Package buildinfo carries release identity stamped in at link time.
package buildinfo

import (
	"runtime"
	"runtime/debug"
)

// Set via -ldflags at release time; see .goreleaser.yaml.
var (
	Version = "0.0.0-dev"
	Commit  = ""
	Date    = ""
)

// Platform is the manifest key for the running host: "linux/amd64".
func Platform() string {
	return runtime.GOOS + "/" + runtime.GOARCH
}

// Info is the stable shape emitted by `nodary version --format json`.
type Info struct {
	Version  string `json:"version"`
	Commit   string `json:"commit,omitempty"`
	Date     string `json:"date,omitempty"`
	Platform string `json:"platform"`
	Go       string `json:"go"`
}

func Get() Info {
	i := Info{
		Version:  Version,
		Commit:   Commit,
		Date:     Date,
		Platform: Platform(),
		Go:       runtime.Version(),
	}
	// A `go install`ed binary carries no ldflags; recover what we can.
	if i.Commit == "" {
		if bi, ok := debug.ReadBuildInfo(); ok {
			for _, s := range bi.Settings {
				switch s.Key {
				case "vcs.revision":
					i.Commit = s.Value
				case "vcs.time":
					if i.Date == "" {
						i.Date = s.Value
					}
				}
			}
		}
	}
	return i
}
