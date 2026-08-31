#!/usr/bin/env node
//
// Launcher for the nodary binary.
//
// The binary itself lives in a per-platform package pulled in through
// optionalDependencies. npm resolves those *silently*: on a platform with no
// matching package it installs nothing at all and leaves this shim to fail with
// whatever error happens next. That is the failure mode this file exists to
// prevent — an unsupported platform must say so, by name, once.

"use strict";

const { spawnSync } = require("node:child_process");
const path = require("node:path");
const fs = require("node:fs");

// npm arch/platform names, not Go's.
const SUPPORTED = {
  "linux-x64": "nodary-linux-x64",
  "linux-arm64": "nodary-linux-arm64",
  "darwin-x64": "nodary-darwin-x64",
  "darwin-arm64": "nodary-darwin-arm64",
};

function key() {
  return `${process.platform}-${process.arch}`;
}

function fail(message) {
  process.stderr.write(`nodary: ${message}\n`);
  process.exit(1);
}

function resolveBinary() {
  const k = key();
  const pkg = SUPPORTED[k];

  if (!pkg) {
    fail(
      `unsupported platform ${k}.\n` +
        `nodary supports: ${Object.keys(SUPPORTED).join(", ")}.\n` +
        `The server and agent additionally require Linux with systemd; ` +
        `see https://github.com/nodarynet/nodary`
    );
  }

  const name = process.platform === "win32" ? "nodary.exe" : "nodary";
  try {
    // Resolve through the package's own manifest: require.resolve on the
    // binary itself fails for a file with no extension.
    const manifest = require.resolve(`${pkg}/package.json`);
    const candidate = path.join(path.dirname(manifest), "bin", name);
    if (fs.existsSync(candidate)) return candidate;
  } catch {
    // fall through to the shared diagnostic below
  }

  fail(
    `the platform package ${pkg} is not installed.\n` +
      `This usually means the install ran with --no-optional, or the package ` +
      `failed to download.\nReinstall with: npm install --include=optional nodary`
  );
}

const binary = resolveBinary();

const result = spawnSync(binary, process.argv.slice(2), { stdio: "inherit" });

if (result.error) {
  fail(`could not execute ${binary}: ${result.error.message}`);
}

// Propagate a fatal signal as the conventional 128+n so exit codes stay
// meaningful to callers (docs/specs/10-cli.md §5).
if (result.signal) {
  process.exit(128 + (require("node:os").constants.signals[result.signal] || 0));
}

process.exit(result.status === null ? 1 : result.status);
