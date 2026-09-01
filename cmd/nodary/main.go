// Command nodary is the single binary containing the nodary server, agent and CLI.
// The role is selected by subcommand; see docs/specs/10-cli.md.
package main

import (
	"os"

	"github.com/nodarynet/nodary/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
