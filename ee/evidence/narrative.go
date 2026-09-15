package evidence

import (
	"bytes"
	"fmt"
	"iter"
	"maps"
	"slices"
	"strings"
	"text/template"
	"time"

	"github.com/nodarynet/nodary/internal/policy"
)

// MemberNarratives is the directory of System Security Plan paragraphs.
const MemberNarratives = "narratives"

// narrative is the text that goes in a plan for one requirement, with this
// install's own values in it.
//
// **A parameter that does not resolve fails the export.** dev/tasks/R9-evidence-remediation.md
// puts it plainly: a narrative naming a value nodary does not hold has to fail
// to render rather than emit a placeholder into a deliverable. `<no value>` in
// a paragraph an assessor reads is worse than no paragraph, because it is
// indistinguishable from a number somebody forgot to fill in — and the template
// runs with missingkey=error so that cannot happen quietly.
type narrative struct {
	// Practice is the Rev 2 identifier this paragraph is about. Every one has
	// to be a practice the crosswalk holds; a test checks it.
	Practice string
	Text     string
}

// facts are the values a narrative may name. Every field is something this
// install actually holds — the active profile's settings and the period the
// bundle covers — so a paragraph cannot describe a configuration nobody has.
type facts struct {
	Profile                string
	MinJustificationLength int
	RequireTOTP            bool
	AuditRetentionDays     int
	UsageRetentionDays     int
	SessionTTLMinutes      int
	TokenMaxTTLDays        int
	AdvisoryDecisionDays   int
	EgressDefault          string
	Install                string
	From, To               string
	Nodes                  int
}

// narratives is one paragraph per mapped requirement.
//
// They are written to be pasted into a plan and then *edited*: each says what
// nodary does, in this install's configuration, and leaves the organizational
// half — who reviews it, how often, and under whose authority — to the reader,
// because that half is not nodary's to assert.
var narratives = []narrative{
	{"3.1.1", `Access to the inference control plane is limited to named local accounts, each
holding one of four roles. Machines are subject to the same rule: a GPU node that enrolls is
recorded in the "pending" state and receives no workload until an administrator approves it,
and the approval records the hardware inventory the node offered as the inventory that was
agreed to. As of this report the fleet holds {{.Nodes}} approved node(s).`},

	{"3.1.2", `Each account holds one of four roles — viewer, user, operator, administrator —
and every administrative verb checks the role before acting. The check is made once, in a
shared core that both the command line and the HTTP interface call, so the two cannot
disagree about what a role permits.`},

	{"3.1.5", `Accounts are created at the least-privileged role unless another is named
explicitly. Configuration changes, backend registration, node approval and account management
require the administrator role; using the inference service does not.`},

	{"3.1.7", `An attempt to perform a privileged function without the role for it is refused
and recorded, with the reason, in the same append-only audit log that records the acts which
succeeded. The refusal and the act are the same kind of record, so a review of privileged
activity sees both.`},

	{"3.1.8", `Unsuccessful sign-in attempts are counted per account and per source address and
are locked out once a threshold is reached; the refusal tells the caller when to try again.
The lockout is applied before the password is verified and before anything is written, so
repeated attempts cannot be used to consume system resources.`},

	{"3.1.11", `Interactive sessions to the web console are held server-side and expire
{{.SessionTTLMinutes}} minutes after they are established under the "{{.Profile}}" policy
profile now in force. Credentials issued to programs expire at no more than
{{.TokenMaxTTLDays}} days.`},

	{"3.1.13", `All administrative access is over TLS. Administrative clients connect to the
control plane over TLS; GPU nodes connect over mutual TLS, presenting a client certificate
issued by the installation's own certificate authority at enrollment.`},

	{"3.3.1", `Every administrative action produces an audit record, written inside the same
database transaction that performs the action, so an action that took effect without being
recorded is not a state the system can reach. Audit records are retained for
{{.AuditRetentionDays}} days and service usage records for {{.UsageRetentionDays}} days under
the "{{.Profile}}" profile. This report covers {{.From}} to {{.To}}.`},

	{"3.3.2", `Each audit record names the account that acted and the means by which it
authenticated — password, issued credential, browser session, node certificate, or local
administration on the host. Accounts are identified by a stable identifier that does not
change if the account is renamed, so activity remains attributable to the same person over
time.`},

	{"3.3.8", `Audit records are chained: each record carries a cryptographic hash of the one
before it, so modifying or deleting a record breaks the chain at the point where it happened
and the break is detectable by anyone holding the records. The exported segment can be
verified independently, using standard tools, without the system that produced it.`},

	{"3.3.9", `Audit retention and pruning require the administrator role, and performing either
is itself an audited act: the record states what was pruned and through which sequence number,
so a deliberate gap in the record is documented rather than silent.`},

	{"3.4.1", `Each applied configuration change writes a revision that carries a complete
snapshot of the configuration and a cryptographic hash of it, so any earlier baseline can be
reproduced exactly and the history verified end to end. The hardware inventory is the
inventory each node offered when it was approved.`},

	{"3.4.2", `Security-relevant settings are held in a named policy profile, and the profile
is enforced by the software rather than documented as guidance. The profile in force for this
report is "{{.Profile}}".`},

	{"3.4.3", `A configuration change is previewed before it is applied. The system renders the
change, produces a cryptographic hash of that rendering, and records the change only against
that hash — so if the system's state moves between the preview and the approval, the change is
refused rather than applied in a form nobody reviewed. Each change is recorded with the
account that approved it and a written justification of at least
{{.MinJustificationLength}} characters.{{if .RequireTOTP}} A second authentication factor is
re-entered at the moment of the change; an existing signed-in session does not satisfy it.{{end}}`},

	{"3.4.5", `Which accounts may change the configuration is enforced by role. That a specific
change was approved, by whom, and for what stated reason is recorded in the audit chain with
the change itself.`},

	{"3.5.1", `People, programs and machines are each identified. People hold named accounts;
programs hold credentials issued to a named account for a named purpose; GPU nodes are
identified by a certificate issued by the installation's certificate authority when the node
enrolled.`},

	{"3.5.2", `People authenticate with a password{{if .RequireTOTP}} and a time-based
one-time code{{end}}. Programs authenticate with an issued bearer credential. Nodes
authenticate with a client certificate over mutual TLS. An unauthenticated request is never
treated as an administrator, including on the machine hosting the control plane.`},

	{"3.5.3", `{{if .RequireTOTP}}Multifactor authentication is required for administrative
actions under the "{{.Profile}}" profile, and the second factor is presented for the action
rather than inherited from the session that is already signed in. An action that legitimately
proceeded without one records why.{{else}}Multifactor authentication is available and is not
required by the "{{.Profile}}" profile now in force; the "regulated" profile requires it.
This is a configuration decision this organization has made and can change.{{end}}`},

	{"3.5.10", `Passwords are stored as PBKDF2-SHA256 derivations with a salt of at least 128
bits, computed by a validated cryptographic module. Issued credentials are stored as a hash
and a short non-secret prefix; the credential itself is displayed once, when it is created,
and cannot be read back from the system afterwards. Passwords and credentials cross the
network only over TLS.`},

	{"3.12.2", `Security advisories affecting the components this installation runs are tracked
against it. An advisory that has not been decided within {{.AdvisoryDecisionDays}} days
becomes an outstanding remediation item by the passage of time rather than by anyone
remembering to raise it, and the decision — to apply, to defer with a reason, or to accept —
is an audited act carrying the account that made it and its justification.`},

	{"3.12.3", `The network isolation of each deployed model is asserted continuously rather
than configured once: the check runs on the node, inside the deployment's own network
namespace, after every start, and its verdict is reported to the control plane. A verdict that
changes in either direction is recorded as an event, so a period during which the control was
not in force remains reviewable after it ends.`},

	{"3.12.4", `This narrative and the control index accompanying it describe how this
installation implements the requirements above, with the values this installation actually
holds. They describe the inference system only; the boundaries, environment and connections of
the wider system remain to be described by this organization.`},

	{"3.13.1", `Each deployed model runs on an isolated network with no route off the machine
hosting it, reachable only by the local gateway process. The default for egress under the
"{{.Profile}}" profile is "{{.EgressDefault}}". The assertion that verifies the isolation runs
inside the deployment's own network namespace, on the machine concerned, rather than being
inferred from configuration held elsewhere.`},

	{"3.13.6", `{{if eq .EgressDefault "deny"}}Network traffic from a deployed model is denied
by default and permitted only by exception under the "{{.Profile}}" profile. Where an
exception is made — a container image built on the control plane, for instance — the
permitted destination is named in advance and what the build actually reached is recorded with
it.{{else}}The "{{.Profile}}" profile now in force sets the egress default to
"{{.EgressDefault}}". The "regulated" profile denies by default; this is a configuration
decision this organization has made and can change.{{end}}`},

	{"3.13.8", `Administrative traffic, inference traffic and the node protocol all cross the
network over TLS, and the node protocol additionally authenticates both ends. A deployed
model's own port is published on the host's loopback interface and is not reachable from off
that machine.`},

	{"3.13.11", `The software is built against the Go cryptographic module validated to FIPS
140-3, and runs with that module in service for every approved algorithm — including the
transport protecting data in transit, the derivation protecting stored passwords, and the
digests protecting the audit chain. The validation belongs to the cryptographic module. This
product is not itself a validated cryptographic module and does not claim to be one.`},
}

// narrativeFiles renders one file per requirement, or fails.
func narrativeFiles(active policy.Profile, opt Options, nodes int) (map[string][]byte, error) {
	f := facts{
		Profile: active.Name, MinJustificationLength: active.MinJustificationLength,
		RequireTOTP: active.RequireTOTP, AuditRetentionDays: active.AuditRetentionDays,
		UsageRetentionDays: active.UsageRetentionDays, SessionTTLMinutes: active.SessionTTLMinutes,
		TokenMaxTTLDays: active.TokenMaxTTLDays, AdvisoryDecisionDays: active.AdvisoryDecisionDays,
		EgressDefault: active.EgressDefault, Install: opt.Install,
		From: opt.From.UTC().Format(time.DateOnly), To: opt.To.UTC().Format(time.DateOnly),
		Nodes: nodes,
	}

	out := map[string][]byte{}
	for _, n := range narratives {
		// missingkey=error is the whole point: a field this template names and
		// facts does not hold stops the export instead of writing "<no value>"
		// into something somebody signs.
		t, err := template.New(n.Practice).Option("missingkey=error").Parse(n.Text)
		if err != nil {
			return nil, fmt.Errorf("narrative %s: %w", n.Practice, err)
		}
		var b bytes.Buffer
		if err := t.Execute(&b, f); err != nil {
			return nil, fmt.Errorf("narrative %s: %w", n.Practice, err)
		}
		body := strings.Join(strings.Fields(b.String()), " ")
		if strings.Contains(body, "<no value>") {
			return nil, fmt.Errorf("narrative %s named a value this install does not hold", n.Practice)
		}
		out[MemberNarratives+"/"+n.Practice+".md"] = []byte(
			"# " + n.Practice + " — " + requirementFor(n.Practice) + "\n\n" + body + "\n")
	}
	return out, nil
}

// requirementFor is the quoted requirement, so a paragraph pasted into a plan
// carries what it is answering.
func requirementFor(id string) string {
	for _, p := range crosswalk {
		if p.ID == id {
			return p.Requirement
		}
	}
	return ""
}

// sortedFiles iterates a member map in name order, because a bundle's manifest
// lists what it holds and an archive whose member order changes between two
// exports of the same data is one whose digests cannot be compared.
func sortedFiles(files map[string][]byte) iter.Seq2[string, []byte] {
	names := slices.Sorted(maps.Keys(files))
	return func(yield func(string, []byte) bool) {
		for _, n := range names {
			if !yield(n, files[n]) {
				return
			}
		}
	}
}
