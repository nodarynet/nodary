package agent

import (
	"regexp"
	"strings"
	"testing"
)

// expandExecStart is systemd's own rule, which is the whole reason this test
// exists: `$FOO` is split at whitespace into separate arguments and `${FOO}` is
// passed as one, never split (systemd.service(5), "Command lines").
func expandExecStart(template string, env map[string]string) []string {
	var line string
	for _, l := range strings.Split(template, "\n") {
		if strings.HasPrefix(l, "ExecStart=") {
			line = strings.TrimPrefix(l, "ExecStart=")
		} else if line != "" && strings.HasSuffix(line, "\\") {
			line = strings.TrimSuffix(line, "\\") + l
		}
	}
	var argv []string
	for _, tok := range strings.Fields(strings.TrimSuffix(line, "\\")) {
		if name, ok := strings.CutPrefix(tok, "${"); ok {
			argv = append(argv, env[strings.TrimSuffix(name, "}")])
			continue
		}
		if name, ok := strings.CutPrefix(tok, "$"); ok {
			argv = append(argv, strings.Fields(env[name])...)
			continue
		}
		argv = append(argv, tok)
	}
	return argv
}

// TestTheUnitTemplateAndTheEnvAreOneContract is the pairing unit.go names and
// nothing held.
//
// The template and the variables plan.go renders are one contract written in
// two files, and R6-14 moved the boundary between them: `--gpus` used to be a
// literal in the template and is now part of NODARY_GPUS, because a card is
// reached by `--gpus device=0` on NVIDIA and `--device /dev/dri/renderD128` on
// AMD — a different flag, not a different value, and a unit file has no
// conditional. Leave the literal behind and every deployment on every node runs
// `nerdctl run --gpus --gpus device=0`, which fails on a GPU host as a
// container that will not start, long after the change that caused it.
func TestTheUnitTemplateAndTheEnvAreOneContract(t *testing.T) {
	nvidia, err := gpuFlag([]int{0, 1}, map[int]GPU{
		0: {Index: 0, Vendor: VendorNVIDIA}, 1: {Index: 1, Vendor: VendorNVIDIA},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	amd, err := gpuFlag([]int{0}, map[int]GPU{
		0: {Index: 0, Vendor: VendorAMD, Render: "/dev/dri/renderD128"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := RenderUnitTemplate("/etc/nodary")
	base := map[string]string{
		"NODARY_ARGS": "/models/m --port=8000", "NODARY_CONTAINER_PORT": "8000",
		"NODARY_ENV": "", "NODARY_IMAGE": "registry/vllm@sha256:abc",
		"NODARY_MODELS_DIR": "/var/lib/nodary/models", "NODARY_MOUNT_PATH": "/models",
		"NODARY_NETWORK": "nodary-isolated", "NODARY_PORT": "8001",
	}

	for _, tc := range []struct {
		name, flag string
		want       []string
	}{
		{"nvidia", nvidia, []string{"--gpus", "device=0,1"}},
		{"amd", amd, []string{"--device", "/dev/dri/renderD128"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := map[string]string{"NODARY_GPUS": tc.flag}
			for k, v := range base {
				env[k] = v
			}
			argv := expandExecStart(tmpl, env)
			if !hasRun(argv, tc.want) {
				t.Errorf("argv = %v\n  want the device argument to arrive as %v", argv, tc.want)
			}
			// The one that a stale template produces, and the only one that
			// looks plausible enough to survive a review.
			for i := 1; i < len(argv); i++ {
				if argv[i] == argv[i-1] && strings.HasPrefix(argv[i], "--") {
					t.Errorf("argv = %v\n  %q appears twice in a row: the template still holds a "+
						"flag that NODARY_GPUS now carries", argv, argv[i])
				}
			}
			// An image reference must never be split, which is the other half
			// of the braced/unbraced rule.
			if !hasRun(argv, []string{env["NODARY_IMAGE"]}) {
				t.Errorf("argv = %v\n  the image did not arrive as one argument", argv)
			}
		})
	}

	// Neither direction of the contract may drift: a variable the template
	// does not read is a setting that looks applied and is not, and one the
	// template reads that nothing writes expands to nothing, silently.
	ref := map[string]bool{}
	for _, m := range regexp.MustCompile(`\$\{?(NODARY_[A-Z_]+)\}?`).FindAllStringSubmatch(tmpl, -1) {
		ref[m[1]] = true
	}
	for k := range base {
		if !ref[k] {
			t.Errorf("plan.go writes %s and the template never reads it", k)
		}
	}
	for k := range ref {
		if _, ok := base[k]; !ok && k != "NODARY_GPUS" {
			t.Errorf("the template reads %s and plan.go never writes it", k)
		}
	}
}

// hasRun reports whether want appears as consecutive arguments in argv.
func hasRun(argv, want []string) bool {
	for i := 0; i+len(want) <= len(argv); i++ {
		found := true
		for j, w := range want {
			if argv[i+j] != w {
				found = false
				break
			}
		}
		if found {
			return true
		}
	}
	return false
}
