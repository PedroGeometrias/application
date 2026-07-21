#!/bin/sh
set -eu

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
private_key=${1:-"$root_dir/backend/data/signing/private.pem"}
public_key=${2:-"$root_dir/backend/data/signing/public.pem"}

mkdir -p "$(dirname "$private_key")" "$(dirname "$public_key")"
umask 077
"$root_dir/native/build/threatcore" keygen "$private_key" "$public_key"
printf 'Created RSA-PSS signing keys:\n  private: %s\n  public:  %s\n' "$private_key" "$public_key"
