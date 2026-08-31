module github.com/nodarynet/nodary

// `go` is the minimum a contributor or downstream packager needs; `toolchain`
// is what a release is actually built with. Keeping them apart means the
// published binaries stay reproducible against one pinned compiler without
// forcing everyone who builds from source onto a toolchain days old.
go 1.25.0

toolchain go1.27.0

require github.com/gowebpki/jcs v1.0.1

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/sys v0.47.0 // indirect
	modernc.org/libc v1.74.4 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
	modernc.org/sqlite v1.57.0 // indirect
)
