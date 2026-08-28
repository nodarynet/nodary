package cli

import (
	"encoding/json"
	"fmt"

	"github.com/nodary/nodary/internal/buildinfo"
)

func buildVersion() string {
	i := buildinfo.Get()
	return fmt.Sprintf("%s (%s)", i.Version, i.Platform)
}

func cmdVersion(e env, args []string) int {
	fs := newFlagSet(e, "version")
	format := formatFlag(fs)
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}

	i := buildinfo.Get()

	if *format == "json" {
		enc := json.NewEncoder(e.stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(i); err != nil {
			fmt.Fprintf(e.stderr, "nodary version: %v\n", err)
			return ExitFailure
		}
		return ExitOK
	}

	fmt.Fprintf(e.stdout, "nodary %s\n", i.Version)
	fmt.Fprintf(e.stdout, "  platform  %s\n", i.Platform)
	fmt.Fprintf(e.stdout, "  go        %s\n", i.Go)
	if i.Commit != "" {
		fmt.Fprintf(e.stdout, "  commit    %s\n", i.Commit)
	}
	if i.Date != "" {
		fmt.Fprintf(e.stdout, "  built     %s\n", i.Date)
	}
	return ExitOK
}
