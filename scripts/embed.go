// Package scripts embeds the standalone shell scripts this repository ships
// beside the binary, so code that needs one at runtime (the install wizard's
// download step, `internal/cli/modelfetch.go`) carries the exact same,
// already-verified implementation rather than a second one written in Go.
//
// stage-model.sh stays a real file at this path, fetchable by `curl` the way
// administering.md's manual path already does — embedding it does not
// change that, it only gives a Go caller its bytes without needing the
// network or a repository checkout to get them.
package scripts

import _ "embed"

//go:embed stage-model.sh
var StageModelSH []byte
