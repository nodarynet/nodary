# These files are frozen

A migration is **content-addressed**. `Migrate` records each file's checksum when
it applies it and refuses to run against a database whose recorded checksum
differs, because an applied migration describes what a live database already
did — editing one makes the record a fiction.

**The file is hashed whole, so a comment counts.** Two words corrected inside a
comment here stopped every existing installation with

    migration checksum does not match the applied schema: 0009_node_certificate
    applied as 99313e52…, embedded copy is e02c49fb…

It happened twice in one day, from two separate tree-wide spelling passes, and
neither was caught by `make check` — every test builds a *fresh* database, and a
fresh database records whatever checksum is embedded. Drift is only visible
against a database that already exists, which means only on somebody's real
installation.

So:

- **Never edit a file in this directory.** Not the SQL, not a comment, not
  whitespace, not spelling. Two of these still read `re-enrolment` and
  `licence`; they stay that way.
- **Correct an existing migration with a new one.** That is what the numbering
  is for.
- Adding one adds a line to `../testdata/migrations.sha256`, which
  `TestAnAppliedMigrationNeverChanges` checks. That is the build-time guard the
  two incidents above went straight through.
