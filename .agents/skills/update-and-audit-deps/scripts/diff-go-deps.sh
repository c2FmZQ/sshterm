#!/usr/bin/env bash
#
# Compare go/go.mod and xterm/package-lock.json against a baseline git ref
# (default: HEAD) and generate source code diffs from GOMODCACHE and npm
# tarballs for all upgraded dependencies, along with their import call sites
# in sshterm and sshterm-server.
#
# Usage:
#   ./diff-go-deps.sh [base-ref] [output-dir]

set -euo pipefail

BASE_REF="${1:-HEAD}"
OUT_DIR="${2:-$(mktemp -d /tmp/sshterm-dep-audit.XXXXXX)}"
mkdir -p "${OUT_DIR}"

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "${REPO_ROOT}"

if [[ -f "${REPO_ROOT}/.goversion" ]]; then
  export GOTOOLCHAIN="go$(cat "${REPO_ROOT}/.goversion")"
fi

parse_gomod() {
  awk '
    /^require \(/ { in_req=1; next }
    in_req && /^\)/ { in_req=0; next }
    /^require [^ (]+ [^ (]+/ { print $2, $3; next }
    in_req && NF >= 2 && $1 !~ /^\/\// { print $1, $2 }
  '
}

OLD_MODS="${OUT_DIR}/old_mods.txt"
NEW_MODS="${OUT_DIR}/new_mods.txt"
SUMMARY="${OUT_DIR}/summary.md"

git show "${BASE_REF}:go/go.mod" | parse_gomod | sort -k1,1 > "${OLD_MODS}"
parse_gomod < go/go.mod | sort -k1,1 > "${NEW_MODS}"

echo "# Upgraded Dependencies (${BASE_REF} -> working tree)" > "${SUMMARY}"
echo "" >> "${SUMMARY}"
echo "Output directory: \`${OUT_DIR}\`" >> "${SUMMARY}"
echo "" >> "${SUMMARY}"
echo "## Go Modules (\`go/go.mod\`)" >> "${SUMMARY}"
echo "" >> "${SUMMARY}"

UPGRADED_GO=0

while read -r mod old_ver new_ver; do
  if [[ "${old_ver}" == "${new_ver}" ]]; then
    continue
  fi
  UPGRADED_GO=$((UPGRADED_GO + 1))
  safe_name="$(echo "${mod}" | tr '/.' '__')"
  diff_file="${OUT_DIR}/${safe_name}.diff"

  echo "### ${mod}: ${old_ver} -> ${new_ver}" >> "${SUMMARY}"

  old_dir=""
  new_dir=""
  if [[ "${old_ver}" != "(added)" ]]; then
    old_dir="$(cd "${REPO_ROOT}/go" && go mod download -json "${mod}@${old_ver}" 2>/dev/null | jq -r '.Dir // empty')"
  fi
  if [[ "${new_ver}" != "(removed)" ]]; then
    new_dir="$(cd "${REPO_ROOT}/go" && go mod download -json "${mod}@${new_ver}" 2>/dev/null | jq -r '.Dir // empty')"
  fi

  echo "- Old Dir: \`${old_dir:-N/A}\`" >> "${SUMMARY}"
  echo "- New Dir: \`${new_dir:-N/A}\`" >> "${SUMMARY}"

  # Find files in sshterm / sshterm-server that import this module or its subpackages.
  echo "- Imported in repository files:" >> "${SUMMARY}"
  matches="$(grep -rnE --include='*.go' "\"${mod}(\"|/)" go/ || true)"
  if [[ -n "${matches}" ]]; then
    echo "${matches}" | sed 's/^/  - `/' | sed 's/$/`/' >> "${SUMMARY}"
  else
    echo "  - (transitive / indirect dependency)" >> "${SUMMARY}"
  fi

  if [[ -n "${old_dir}" && -n "${new_dir}" && -d "${old_dir}" && -d "${new_dir}" ]]; then
    diff -ruN \
      --exclude='*_test.go' \
      --exclude='.git*' \
      "${old_dir}" "${new_dir}" > "${diff_file}" || true
    lines="$(wc -l < "${diff_file}")"
    echo "- Non-test Go source diff: \`${diff_file}\` (${lines} lines)" >> "${SUMMARY}"
  fi
  echo "" >> "${SUMMARY}"
done < <(
  join -a1 -a2 -e '(none)' -o '0,1.2,2.2' "${OLD_MODS}" "${NEW_MODS}" |
    awk '$2 != $3 {
      old = ($2 == "(none)" ? "(added)" : $2)
      new = ($3 == "(none)" ? "(removed)" : $3)
      print $1, old, new
    }'
)

if [[ "${UPGRADED_GO}" -eq 0 ]]; then
  echo "No Go module version changes detected in \`go/go.mod\` relative to \`${BASE_REF}\`." >> "${SUMMARY}"
  echo "" >> "${SUMMARY}"
fi

echo "## NPM Packages (\`xterm/package-lock.json\`)" >> "${SUMMARY}"
echo "" >> "${SUMMARY}"

UPGRADED_NPM=0

if git cat-file -e "${BASE_REF}:xterm/package-lock.json" 2>/dev/null && [[ -f xterm/package-lock.json ]]; then
  while IFS=$'\t' read -r pkg_key pkg_name old_ver new_ver old_resolved new_resolved dep_tier; do
    if [[ -z "${pkg_key}" ]]; then
      continue
    fi
    UPGRADED_NPM=$((UPGRADED_NPM + 1))
    safe_name="$(echo "${pkg_key}" | tr '/@.' '___')"
    diff_file="${OUT_DIR}/npm_${safe_name}.diff"
    pkg_work_dir="${OUT_DIR}/npm/${safe_name}"
    old_dir=""
    new_dir=""

    echo "### ${pkg_name} (\`${pkg_key}\`, ${dep_tier}): ${old_ver} -> ${new_ver}" >> "${SUMMARY}"

    if [[ "${old_ver}" != "(added)" && "${old_resolved}" != "-" && -n "${old_resolved}" ]]; then
      old_dir="${pkg_work_dir}/old"
      mkdir -p "${old_dir}"
      curl -fsSL "${old_resolved}" | tar -xz -C "${old_dir}" --strip-components=1
    fi
    if [[ "${new_ver}" != "(removed)" && "${new_resolved}" != "-" && -n "${new_resolved}" ]]; then
      new_dir="${pkg_work_dir}/new"
      mkdir -p "${new_dir}"
      curl -fsSL "${new_resolved}" | tar -xz -C "${new_dir}" --strip-components=1
    fi

    echo "- Old Dir: \`${old_dir:-N/A}\`" >> "${SUMMARY}"
    echo "- New Dir: \`${new_dir:-N/A}\`" >> "${SUMMARY}"

    if [[ -n "${new_dir}" && -f "${new_dir}/package.json" ]]; then
      lifecycle_scripts="$(jq -r '.scripts // {} | to_entries[] | select(.key | test("^(pre|post)?install$|^prepare$")) | "\(.key): \(.value)"' "${new_dir}/package.json" 2>/dev/null || true)"
      if [[ -n "${lifecycle_scripts}" ]]; then
        echo "- **WARNING - Install lifecycle scripts in \`package.json\`**:" >> "${SUMMARY}"
        echo "${lifecycle_scripts}" | sed 's/^/  - `/' | sed 's/$/`/' >> "${SUMMARY}"
      fi
    fi

    if [[ -n "${old_dir}" && -n "${new_dir}" && -d "${old_dir}" && -d "${new_dir}" ]]; then
      diff -ruN \
        --exclude='*.map' \
        --exclude='.git*' \
        "${old_dir}" "${new_dir}" > "${diff_file}" || true
      lines="$(wc -l < "${diff_file}")"
      echo "- Source diff: \`${diff_file}\` (${lines} lines)" >> "${SUMMARY}"
    fi
    echo "" >> "${SUMMARY}"
  done < <(
    jq -rn \
      --slurpfile old <(git show "${BASE_REF}:xterm/package-lock.json") \
      --slurpfile new xterm/package-lock.json '
      ($old[0].packages // {}) as $op |
      ($new[0].packages // {}) as $np |
      ([($op | keys[]), ($np | keys[])] | unique[]) as $k |
      select($k != "") |
      ($op[$k] // null) as $o |
      ($np[$k] // null) as $n |
      select(($o.version // "(added)") != ($n.version // "(removed)")) |
      [
        $k,
        ($k | sub("^.*node_modules/"; "")),
        ($o.version // "(added)"),
        ($n.version // "(removed)"),
        ($o.resolved // "-"),
        ($n.resolved // "-"),
        (if ($n // $o).dev then "dev" else "prod" end)
      ] | @tsv
    '
  )
fi

if [[ "${UPGRADED_NPM}" -eq 0 ]]; then
  echo "No npm package version changes detected in \`xterm/package-lock.json\` relative to \`${BASE_REF}\`." >> "${SUMMARY}"
  echo "" >> "${SUMMARY}"
fi

echo "Audit summary written to: ${SUMMARY} (${UPGRADED_GO} Go module(s), ${UPGRADED_NPM} npm package(s) changed)"
