# keepass-merge

Small CLI for merging several KeePass `.kdbx` databases into one local vault.

It preserves group structure, skips exact duplicate entries, and keeps conflicting entries by renaming the later one with a numeric suffix such as `Email (2)`.

## Safety

No vault contents are uploaded or sent over the network. The tool reads local files, writes one encrypted output database, and exits.

This repository intentionally does not include sample password databases. Tests generate temporary synthetic `.kdbx` files at runtime, and `.gitignore` blocks `*.kdbx`, key files, common input folders, and generated outputs.

## Install

```sh
go install github.com/s04/keepass-merge@latest
```

Or build locally:

```sh
go build -o keepass-merge .
```

## Usage

Put the databases you want to merge in a local folder, then run:

```sh
keepass-merge --input-dir ./kdbx_files --output ./merged.kdbx
```

Options:

```text
--input-dir string   directory containing .kdbx files to merge (default "kdbx_files")
--output string      path for the merged KeePass database (default "merged.kdbx")
--root-name string   name of the root group in the merged database (default "Merged Root")
--force              overwrite the output file if it already exists
--per-file-passwords prompt for a separate input password for each database
--skip-invalid       skip input databases that cannot be opened
--verbose            print per-file entry and group counts
```

## Passwords

The CLI asks for passwords at runtime instead of accepting them as command-line flags.

```text
Input vault password:
Output vault password (leave blank to reuse input password):
Confirm output vault password:
```

By default, the input password unlocks every source database in `--input-dir`.

The output password encrypts the merged database. Press Enter at the output prompt to reuse the input password. If you type a separate output password, the CLI asks for confirmation before writing the merged vault.

If the input databases have different passwords, use `--per-file-passwords`:

```sh
keepass-merge --input-dir ./kdbx_files --output ./merged.kdbx --per-file-passwords
```

That changes the input prompts to one prompt per source database:

```text
Input vault password for old.kdbx:
Input vault password for work.kdbx:
Output vault password (leave blank to reuse the first input password):
Confirm output vault password:
```

For non-interactive use:

```sh
# Reuse the input password for the output vault.
printf '%s\n\n' "$KEEPASS_INPUT_PASSWORD" \
  | keepass-merge --input-dir ./kdbx_files --output ./merged.kdbx

# Use a separate output password.
printf '%s\n%s\n%s\n' "$KEEPASS_INPUT_PASSWORD" "$KEEPASS_OUTPUT_PASSWORD" "$KEEPASS_OUTPUT_PASSWORD" \
  | keepass-merge --input-dir ./kdbx_files --output ./merged.kdbx

# Two input vaults with different passwords, then a separate output password.
printf '%s\n%s\n%s\n%s\n' "$KEEPASS_OLD_PASSWORD" "$KEEPASS_WORK_PASSWORD" "$KEEPASS_OUTPUT_PASSWORD" "$KEEPASS_OUTPUT_PASSWORD" \
  | keepass-merge --input-dir ./kdbx_files --output ./merged.kdbx --per-file-passwords
```

By default, the merge stops if any input database cannot be opened. Use `--skip-invalid` only when you intentionally want a partial merge.

## Duplicate Handling

- Same title and same password: keep one copy.
- Same title and different password: keep both, renaming the later entry.
- Same group name: merge entries into that group.
- New group name: copy the group into the output database.

## Development

```sh
go test ./...
```

The integration test creates mock KeePass databases in a temporary directory, merges them, and reopens the merged output. No fixture vaults are stored in the repository.

Make a backup before merging real password databases.
