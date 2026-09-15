package evidence

// The crosswalk from what a nodary install produces to the NIST SP 800-171
// Revision 2 security requirements it is evidence for.
//
// **Revision 2, and it is a withdrawn publication.** NIST withdrew Rev 2 on
// 14 May 2024, superseded by Rev 3. CMMC assesses Level 2 against Rev 2's 110
// requirements regardless — 32 CFR part 170 is written against them, and the
// rulemaking that would move CMMC to Rev 3 is in progress and not in force. So
// the identifiers here are the ones a System Security Plan cites today, and
// they will renumber when that lands. [R9-20](../../dev/tasks/R9-evidence-remediation.md)
//
// **Transcribed, not recalled.** Every identifier and every quoted requirement
// comes from NIST's own published CSV of the Rev 2 security requirements
// (`sp800-171r2-security-reqs.csv`, from the publication's page at csrc.nist.gov).
// dev/plans/pivot-cmmc.md §5 is the reason that mattered enough to wait for:
// this is the one artifact in the product where being approximately right is
// worse than being absent, because a customer pastes it into a plan an assessor
// reads.
//
// **A row says where evidence lives. It does not discharge a requirement.**
// Every requirement still has an owner inside the operating organization, and
// the accuracy of the plan is theirs. A row means: when the `regulated` profile
// is active, this is the mechanism, and this is the artifact an assessor would
// be shown.

// Practice is one 800-171 Rev 2 requirement this install produces evidence for.
type Practice struct {
	// ID is the Rev 2 identifier an SSP cites — `3.4.3`. Not the CMMC
	// `AC.L2-3.1.1` form: that adds a family abbreviation and a level, and
	// deriving one here would be exactly the kind of near-enough transcription
	// this table exists to avoid.
	ID string `json:"practice"`
	// Family is NIST's own family name for the requirement.
	Family string `json:"family"`
	// Requirement is the requirement statement, quoted from the publication.
	Requirement string `json:"requirement"`
	// Mechanism is what nodary does. Written so that it can be checked against
	// the running system rather than believed.
	Mechanism string `json:"mechanism"`
	// Members are the bundle members holding the evidence, and an empty list
	// means the mechanism is real and the bundle carries no artifact for it —
	// which is a thing worth being able to say.
	Members []string `json:"members"`
}

// crosswalk is the whole claim, in one place, so the bundle an assessor reads
// and the page a buyer reads cannot drift. A test asserts they agree.
var crosswalk = []Practice{
	{
		ID: "3.1.1", Family: "Access Control",
		Requirement: "Limit system access to authorized users, processes acting on behalf of " +
			"authorized users, and devices (including other systems).",
		Mechanism: "Local accounts with roles, and — the devices half — a node that enrolls is " +
			"`pending` until an administrator approves it, and receives no desired state until " +
			"then. Approval records the inventory the node offered as what was agreed to.",
		Members: []string{MemberIdentity, MemberNodes},
	},
	{
		ID: "3.1.2", Family: "Access Control",
		Requirement: "Limit system access to the types of transactions and functions that " +
			"authorized users are permitted to execute.",
		Mechanism: "Four roles — viewer, user, operator, admin — checked on every verb by one " +
			"authorization function, in the core both the CLI and the HTTP API call. Neither " +
			"front end carries its own copy of the table.",
		Members: []string{MemberIdentity, MemberChain},
	},
	{
		ID: "3.1.5", Family: "Access Control",
		Requirement: "Employ the principle of least privilege, including for specific security " +
			"functions and privileged accounts.",
		Mechanism: "A new account is the least-privileged role unless one is named. Configuration, " +
			"backend registration, node approval and account management are admin-only; running " +
			"inference is not.",
		Members: []string{MemberIdentity},
	},
	{
		ID: "3.1.7", Family: "Access Control",
		Requirement: "Prevent non-privileged users from executing privileged functions and " +
			"capture the execution of such functions in audit logs.",
		Mechanism: "A refused act is recorded with its reason, not merely refused — so the chain " +
			"carries the attempt as well as the privileged acts that succeeded.",
		Members: []string{MemberChain},
	},
	{
		ID: "3.1.8", Family: "Access Control",
		Requirement: "Limit unsuccessful logon attempts.",
		Mechanism: "Failed sign-ins lock out per account and per source after a threshold, and " +
			"the refusal carries a Retry-After. The lockout is before the password hash is " +
			"computed and before anything is written, so it cannot be used to spend the control " +
			"plane's writer or to grow the chain.",
		Members: []string{MemberChain},
	},
	{
		ID: "3.1.11", Family: "Access Control",
		Requirement: "Terminate (automatically) a user session after a defined condition.",
		Mechanism: "Console sessions are server-side and expire on a lifetime the active policy " +
			"profile sets. A restart of the control plane ends them all, because they are held " +
			"in memory deliberately.",
		Members: []string{MemberChain},
	},
	{
		ID: "3.1.13", Family: "Access Control",
		Requirement: "Employ cryptographic mechanisms to protect the confidentiality of remote " +
			"access sessions.",
		Mechanism: "Every administrative path is TLS: the console and the HTTP API on the " +
			"control plane's certificate, and the agent protocol on mutual TLS against a CA the " +
			"install generates.",
		Members: []string{MemberNodes},
	},
	{
		ID: "3.3.1", Family: "Audit and Accountability",
		Requirement: "Create and retain system audit logs and records to the extent needed to " +
			"enable the monitoring, analysis, investigation, and reporting of unlawful or " +
			"unauthorized system activity",
		Mechanism: "Every administrative act writes a record inside the same transaction that " +
			"performs it, so an act that happened and was not recorded is not a state this can " +
			"reach. Retention is a policy setting, and audit and usage retention are separate.",
		Members: []string{MemberChain, MemberVerify},
	},
	{
		ID: "3.3.2", Family: "Audit and Accountability",
		Requirement: "Ensure that the actions of individual system users can be uniquely traced " +
			"to those users, so they can be held accountable for their actions.",
		Mechanism: "Each record carries the actor's account id and how they authenticated — " +
			"password, token, session, node certificate or local root — and a credential " +
			"resolves to the person it was issued to. The id is stable across a rename.",
		Members: []string{MemberChain, MemberIdentity},
	},
	{
		ID: "3.3.8", Family: "Audit and Accountability",
		Requirement: "Protect audit information and audit logging tools from unauthorized " +
			"access, modification, and deletion.",
		Mechanism: "Each record hashes the one before it, so an edit or a deletion breaks the " +
			"chain at the point it happened. The bundle's segment verifies standalone with " +
			"`sha256sum` and `minisign` and needs neither nodary nor the database it came from.",
		Members: []string{MemberChain, MemberVerify},
	},
	{
		ID: "3.3.9", Family: "Audit and Accountability",
		Requirement: "Limit management of audit logging functionality to a subset of privileged " +
			"users.",
		Mechanism: "Retention and pruning are admin-only and are themselves recorded acts: the " +
			"chain says what was pruned and through which sequence, so a gap is a documented " +
			"gap rather than an absence.",
		Members: []string{MemberChain},
	},
	{
		ID: "3.4.1", Family: "Configuration Management",
		Requirement: "Establish and maintain baseline configurations and inventories of " +
			"organizational systems (including hardware, software, firmware, and documentation) " +
			"throughout the respective system development life cycles.",
		Mechanism: "Every `config apply` writes a revision carrying a complete configuration " +
			"snapshot and its hash, so any past baseline can be produced exactly. The hardware " +
			"inventory is what each node offered at approval.",
		Members: []string{MemberRevisions, MemberNodes},
	},
	{
		ID: "3.4.2", Family: "Configuration Management",
		Requirement: "Establish and enforce security configuration settings for information " +
			"technology products employed in organizational systems.",
		Mechanism: "A policy profile — `default` or `regulated` — sets what is required and what " +
			"is refused, and it is enforced rather than advisory. The bundle records which " +
			"profile was active when it was made.",
		Members: []string{MemberControls},
	},
	{
		ID: "3.4.3", Family: "Configuration Management",
		Requirement: "Track, review, approve or disapprove, and log changes to organizational " +
			"systems.",
		Mechanism: "The attestation ceremony, and this is the requirement it was built for. A " +
			"change is rendered as a preview, hashed, approved with a justification and — under " +
			"`regulated` — a re-entered authentication code, and applied only against that hash. " +
			"State that moved between the preview and the apply refuses the act rather than " +
			"silently applying something else.",
		Members: []string{MemberRevisions, MemberChain},
	},
	{
		ID: "3.4.5", Family: "Configuration Management",
		Requirement: "Define, document, approve, and enforce physical and logical access " +
			"restrictions associated with changes to organizational systems.",
		Mechanism: "Who may change what is the role table; that a change was approved, by whom " +
			"and why, is the attested record. The two are the same mechanism seen from either end.",
		Members: []string{MemberChain, MemberRevisions},
	},
	{
		ID: "3.5.1", Family: "Identification and Authentication",
		Requirement: "Identify system users, processes acting on behalf of users, and devices.",
		Mechanism: "Users, credentials issued to a named user for a named purpose — including " +
			"unattended ones a script holds — and nodes identified by a certificate the control " +
			"plane's own CA issued at enrollment.",
		Members: []string{MemberIdentity, MemberNodes},
	},
	{
		ID: "3.5.2", Family: "Identification and Authentication",
		Requirement: "Authenticate (or verify) the identities of users, processes, or devices, " +
			"as a prerequisite to allowing access to organizational systems.",
		Mechanism: "Passwords for people, bearer tokens for programs, and mutual TLS for nodes. " +
			"An unauthenticated request is never treated as an administrator, including on the " +
			"machine hosting the control plane.",
		Members: []string{MemberIdentity, MemberNodes},
	},
	{
		ID: "3.5.3", Family: "Identification and Authentication",
		Requirement: "Use multifactor authentication for local and network access to privileged " +
			"accounts and for network access to non-privileged accounts.",
		Mechanism: "TOTP, and under `regulated` it is re-entered for the act rather than " +
			"inherited from the session: a cookie proves somebody signed in at some point, and a " +
			"code proves a person was present for this change. An act that legitimately carried " +
			"no code records why.",
		Members: []string{MemberChain, MemberIdentity},
	},
	{
		ID: "3.5.10", Family: "Identification and Authentication",
		Requirement: "Store and transmit only cryptographically-protected passwords.",
		Mechanism: "PBKDF2-SHA256 with a salt of at least 128 bits, through Go's validated " +
			"cryptographic module. A credential is stored as a hash and a prefix; the plaintext " +
			"is displayed once, at creation, and there is nothing to read it back from.",
		Members: []string{MemberIdentity},
	},
	{
		ID: "3.12.2", Family: "Security Assessment",
		Requirement: "Develop and implement plans of action designed to correct deficiencies and " +
			"reduce or eliminate vulnerabilities in organizational systems.",
		Mechanism: "An advisory that has not been decided within the window the profile sets " +
			"becomes a plan-of-action item by the clock rather than by somebody remembering. The " +
			"decision itself is an attested act with a justification.",
		Members: []string{MemberRemediation, MemberChain},
	},
	{
		ID: "3.12.3", Family: "Security Assessment",
		Requirement: "Monitor security controls on an ongoing basis to ensure the continued " +
			"effectiveness of the controls.",
		Mechanism: "The egress assertion runs on the node after every deployment start and its " +
			"verdict rides the heartbeat, so the control is checked continuously rather than " +
			"configured once. A verdict that moves in either direction is an event in the chain, " +
			"which is how a window where the control was not in force stays reviewable afterwards.",
		Members: []string{MemberChain, MemberNodes},
	},
	{
		ID: "3.12.4", Family: "Security Assessment",
		Requirement: "Develop, document, and periodically update system security plans that " +
			"describe system boundaries, system environments of operation, how security " +
			"requirements are implemented, and the relationships with or connections to other " +
			"systems.",
		Mechanism: "The bundle's narratives describe how this install implements the " +
			"requirements above, filled with this install's own values rather than with " +
			"placeholders. The plan is the organization's document; these are the paragraphs " +
			"about nodary that go in it.",
		Members: []string{MemberControlsMD},
	},
	{
		ID: "3.13.1", Family: "System and Communications Protection",
		Requirement: "Monitor, control, and protect communications (i.e., information " +
			"transmitted or received by organizational systems) at the external boundaries and " +
			"key internal boundaries of organizational systems.",
		Mechanism: "A deployment runs on a network with no route off the machine, and the " +
			"assertion that proves it runs inside that deployment's own network namespace. The " +
			"boundary is enforced where it is drawn rather than described in a document.",
		Members: []string{MemberChain, MemberNodes},
	},
	{
		ID: "3.13.6", Family: "System and Communications Protection",
		Requirement: "Deny network communications traffic by default and allow network " +
			"communications traffic by exception (i.e., deny all, permit by exception).",
		Mechanism: "Under `regulated` the egress default is deny, and a derived image is built " +
			"behind an allowlist naming the one index it may reach. What a build reached is part " +
			"of its record.",
		Members: []string{MemberChain},
	},
	{
		ID: "3.13.8", Family: "System and Communications Protection",
		Requirement: "Implement cryptographic mechanisms to prevent unauthorized disclosure of " +
			"CUI during transmission unless otherwise protected by alternative physical " +
			"safeguards.",
		Mechanism: "Inference and administration both cross the network over TLS, and the agent " +
			"protocol is mutual TLS. A deployment's own port is published on loopback and is not " +
			"reachable from off the machine.",
		Members: []string{MemberNodes},
	},
	{
		ID: "3.13.11", Family: "System and Communications Protection",
		Requirement: "Employ FIPS-validated cryptography when used to protect the " +
			"confidentiality of CUI.",
		Mechanism: "Every channel ships a binary built against Go's validated FIPS 140-3 " +
			"cryptographic module, running with it in service for every approved algorithm. " +
			"**nodary itself is not a validated product and will not become one** — the " +
			"validation belongs to the module, and a claim that blurs the two is the kind this " +
			"table exists to avoid.",
		Members: []string{MemberManifest},
	},
}
