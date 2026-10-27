#!/bin/sh
# Generates shell completions into completions/ for release packaging.
set -eu
rm -rf completions
mkdir completions
for sh in bash zsh fish; do
  go run ./cmd/whycant completion "$sh" > "completions/whycant.$sh"
done
