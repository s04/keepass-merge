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
--verbose            print per-file entry and group counts
```

The password prompt is hidden when running in a terminal. All input databases must use the same password.

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
