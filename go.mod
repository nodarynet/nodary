module github.com/nodarynet/nodary

// `go` is the minimum a contributor or downstream packager needs; `toolchain`
// is what a release is actually built with. Keeping them apart means the
// published binaries stay reproducible against one pinned compiler without
// forcing everyone who builds from source onto a toolchain days old.
go 1.25

toolchain go1.27.0

require github.com/gowebpki/jcs v1.0.1
