package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tobischo/gokeepasslib/v3"
	w "github.com/tobischo/gokeepasslib/v3/wrappers"
	"golang.org/x/term"
)

type options struct {
	InputDir         string
	Output           string
	RootName         string
	Force            bool
	PerFilePasswords bool
	SkipInvalid      bool
	Verbose          bool
}

type inputVault struct {
	Path     string
	Password string
}

type mergeStats struct {
	FilesProcessed int
	FilesSkipped   int
	EntriesBefore  int
	GroupsBefore   int
	EntriesAfter   int
	GroupsAfter    int
}

func main() {
	opts := parseFlags()
	if err := run(opts, os.Stdin, os.Stdout); err != nil {
		log.Fatal(err)
	}
}

func parseFlags() options {
	opts := options{}
	flag.StringVar(&opts.InputDir, "input-dir", "kdbx_files", "directory containing .kdbx files to merge")
	flag.StringVar(&opts.Output, "output", "merged.kdbx", "path for the merged KeePass database")
	flag.StringVar(&opts.RootName, "root-name", "Merged Root", "name of the root group in the merged database")
	flag.BoolVar(&opts.Force, "force", false, "overwrite the output file if it already exists")
	flag.BoolVar(&opts.PerFilePasswords, "per-file-passwords", false, "prompt for a separate input password for each database")
	flag.BoolVar(&opts.SkipInvalid, "skip-invalid", false, "skip input databases that cannot be opened")
	flag.BoolVar(&opts.Verbose, "verbose", false, "print per-file entry and group counts")
	flag.Parse()
	return opts
}

func run(opts options, stdin io.Reader, stdout io.Writer) error {
	if strings.TrimSpace(opts.InputDir) == "" {
		return errors.New("input-dir must not be empty")
	}
	if strings.TrimSpace(opts.Output) == "" {
		return errors.New("output must not be empty")
	}
	if !opts.Force {
		if _, err := os.Stat(opts.Output); err == nil {
			return fmt.Errorf("output file %q already exists; pass --force to overwrite it", opts.Output)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("checking output file: %w", err)
		}
	}

	files, err := findKDBXFiles(opts.InputDir)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no .kdbx files found in %q", opts.InputDir)
	}

	inputs, outputPassword, err := readPasswords(stdin, stdout, files, opts.PerFilePasswords)
	if err != nil {
		return err
	}

	stats, mergedDB, err := mergeFiles(inputs, outputPassword, opts.RootName, opts.SkipInvalid, opts.Verbose, stdout)
	if err != nil {
		return err
	}
	if err := writeDatabase(opts.Output, mergedDB); err != nil {
		return err
	}

	fmt.Fprintln(stdout, "\nMerge completed:")
	fmt.Fprintf(stdout, "Files processed: %d\n", stats.FilesProcessed)
	if stats.FilesSkipped > 0 {
		fmt.Fprintf(stdout, "Files skipped: %d\n", stats.FilesSkipped)
	}
	fmt.Fprintf(stdout, "Total entries before merge: %d\n", stats.EntriesBefore)
	fmt.Fprintf(stdout, "Total groups before merge: %d\n", stats.GroupsBefore)
	fmt.Fprintf(stdout, "Entries in merged database: %d\n", stats.EntriesAfter)
	fmt.Fprintf(stdout, "Groups in merged database: %d\n", stats.GroupsAfter)
	fmt.Fprintf(stdout, "Merged database saved as %s\n", opts.Output)

	return nil
}

func findKDBXFiles(inputDir string) ([]string, error) {
	files, err := filepath.Glob(filepath.Join(inputDir, "*.kdbx"))
	if err != nil {
		return nil, fmt.Errorf("finding .kdbx files: %w", err)
	}
	sort.Strings(files)
	return files, nil
}

type passwordPrompter struct {
	stdin    io.Reader
	stdout   io.Writer
	buffered *bufio.Reader
}

func newPasswordPrompter(stdin io.Reader, stdout io.Writer) *passwordPrompter {
	return &passwordPrompter{
		stdin:    stdin,
		stdout:   stdout,
		buffered: bufio.NewReader(stdin),
	}
}

func readPasswords(stdin io.Reader, stdout io.Writer, files []string, perFilePasswords bool) ([]inputVault, string, error) {
	prompter := newPasswordPrompter(stdin, stdout)
	if perFilePasswords {
		return readPerFilePasswords(prompter, files)
	}
	return readSharedInputPassword(prompter, files)
}

func readSharedInputPassword(prompter *passwordPrompter, files []string) ([]inputVault, string, error) {
	inputPassword, err := prompter.read("Input vault password: ")
	if err != nil {
		return nil, "", err
	}
	if inputPassword == "" {
		return nil, "", errors.New("input vault password must not be empty")
	}

	outputPassword, err := readOutputPassword(prompter, inputPassword, "input password")
	if err != nil {
		return nil, "", err
	}

	inputs := make([]inputVault, 0, len(files))
	for _, file := range files {
		inputs = append(inputs, inputVault{
			Path:     file,
			Password: inputPassword,
		})
	}
	return inputs, outputPassword, nil
}

func readPerFilePasswords(prompter *passwordPrompter, files []string) ([]inputVault, string, error) {
	inputs := make([]inputVault, 0, len(files))
	var firstInputPassword string

	for _, file := range files {
		inputPassword, err := prompter.read(fmt.Sprintf("Input vault password for %s: ", filepath.Base(file)))
		if err != nil {
			return nil, "", err
		}
		if inputPassword == "" {
			return nil, "", fmt.Errorf("input vault password for %s must not be empty", filepath.Base(file))
		}
		if firstInputPassword == "" {
			firstInputPassword = inputPassword
		}
		inputs = append(inputs, inputVault{
			Path:     file,
			Password: inputPassword,
		})
	}

	outputPassword, err := readOutputPassword(prompter, firstInputPassword, "the first input password")
	if err != nil {
		return nil, "", err
	}
	return inputs, outputPassword, nil
}

func readOutputPassword(prompter *passwordPrompter, fallbackPassword, fallbackLabel string) (string, error) {
	outputPassword, err := prompter.read(fmt.Sprintf("Output vault password (leave blank to reuse %s): ", fallbackLabel))
	if err != nil {
		return "", err
	}
	if outputPassword == "" {
		return fallbackPassword, nil
	}

	confirmedOutputPassword, err := prompter.read("Confirm output vault password: ")
	if err != nil {
		return "", err
	}
	if outputPassword != confirmedOutputPassword {
		return "", errors.New("output vault passwords do not match")
	}

	return outputPassword, nil
}

func (p *passwordPrompter) read(prompt string) (string, error) {
	fmt.Fprint(p.stdout, prompt)

	if file, ok := p.stdin.(*os.File); ok && term.IsTerminal(int(file.Fd())) {
		passwordBytes, err := term.ReadPassword(int(file.Fd()))
		fmt.Fprintln(p.stdout)
		if err != nil {
			return "", fmt.Errorf("reading password: %w", err)
		}
		return string(passwordBytes), nil
	}

	password, err := p.buffered.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("reading password: %w", err)
	}
	return strings.TrimRight(password, "\r\n"), nil
}

func mergeFiles(inputs []inputVault, outputPassword, rootName string, skipInvalid, verbose bool, stdout io.Writer) (mergeStats, *gokeepasslib.Database, error) {
	stats := mergeStats{}
	mergedDB := newDatabase(outputPassword, rootName)

	for _, input := range inputs {
		if verbose {
			fmt.Fprintf(stdout, "Processing file: %s\n", input.Path)
		}

		db, err := openDatabase(input.Path, input.Password)
		if err != nil {
			if !skipInvalid {
				return stats, nil, fmt.Errorf("opening %s: %w", input.Path, err)
			}
			stats.FilesSkipped++
			fmt.Fprintf(stdout, "Skipping %s: %v\n", input.Path, err)
			continue
		}

		entries, groups := countEntriesAndGroups(&db.Content.Root.Groups[0])
		stats.EntriesBefore += entries
		stats.GroupsBefore += groups
		stats.FilesProcessed++

		if verbose {
			fmt.Fprintf(stdout, "  Entries: %d, Groups: %d\n", entries, groups)
		}

		mergeGroups(&mergedDB.Content.Root.Groups[0], &db.Content.Root.Groups[0])
	}

	if stats.FilesProcessed == 0 {
		return stats, nil, errors.New("no databases were merged successfully")
	}

	stats.EntriesAfter, stats.GroupsAfter = countEntriesAndGroups(&mergedDB.Content.Root.Groups[0])
	return stats, mergedDB, nil
}

func newDatabase(password, rootName string) *gokeepasslib.Database {
	if strings.TrimSpace(rootName) == "" {
		rootName = "Merged Root"
	}

	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials(password)
	db.Content = &gokeepasslib.DBContent{
		Meta: gokeepasslib.NewMetaData(),
		Root: &gokeepasslib.RootData{
			Groups: []gokeepasslib.Group{gokeepasslib.NewGroup()},
		},
	}
	db.Content.Root.Groups[0].Name = rootName
	return db
}

func openDatabase(path, password string) (*gokeepasslib.Database, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials(password)
	if err := gokeepasslib.NewDecoder(f).Decode(db); err != nil {
		return nil, err
	}
	db.UnlockProtectedEntries()
	return db, nil
}

func writeDatabase(path string, db *gokeepasslib.Database) error {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("creating output directory: %w", err)
		}
	}

	outFile, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating merged file: %w", err)
	}
	defer outFile.Close()

	db.LockProtectedEntries()
	if err := gokeepasslib.NewEncoder(outFile).Encode(db); err != nil {
		return fmt.Errorf("encoding merged database: %w", err)
	}
	return nil
}

func countEntriesAndGroups(group *gokeepasslib.Group) (int, int) {
	entries := len(group.Entries)
	groups := 1

	for _, subgroup := range group.Groups {
		subEntries, subGroups := countEntriesAndGroups(&subgroup)
		entries += subEntries
		groups += subGroups
	}

	return entries, groups
}

func mergeGroups(targetGroup, sourceGroup *gokeepasslib.Group) {
	for _, entry := range sourceGroup.Entries {
		existingEntry := findEntry(targetGroup, entry.GetTitle())
		if existingEntry == nil {
			targetGroup.Entries = append(targetGroup.Entries, entry)
			continue
		}

		if existingEntry.GetPassword() != entry.GetPassword() {
			newTitle := enumerateTitle(targetGroup, entry.GetTitle())
			entry.Values = updateValue(entry.Values, "Title", newTitle)
			targetGroup.Entries = append(targetGroup.Entries, entry)
		}
	}

	for _, group := range sourceGroup.Groups {
		existingGroup := findGroup(targetGroup, group.Name)
		if existingGroup == nil {
			targetGroup.Groups = append(targetGroup.Groups, group)
			continue
		}
		mergeGroups(existingGroup, &group)
	}
}

func findEntry(group *gokeepasslib.Group, title string) *gokeepasslib.Entry {
	for i := range group.Entries {
		if group.Entries[i].GetTitle() == title {
			return &group.Entries[i]
		}
	}
	return nil
}

func findGroup(group *gokeepasslib.Group, name string) *gokeepasslib.Group {
	for i := range group.Groups {
		if group.Groups[i].Name == name {
			return &group.Groups[i]
		}
	}
	return nil
}

func enumerateTitle(group *gokeepasslib.Group, title string) string {
	count := 1
	newTitle := title
	for findEntry(group, newTitle) != nil {
		count++
		newTitle = fmt.Sprintf("%s (%d)", title, count)
	}
	return newTitle
}

func updateValue(values []gokeepasslib.ValueData, key, newValue string) []gokeepasslib.ValueData {
	for i, v := range values {
		if v.Key == key {
			values[i].Value.Content = newValue
			return values
		}
	}

	return append(values, gokeepasslib.ValueData{
		Key: key,
		Value: gokeepasslib.V{
			Content:   newValue,
			Protected: w.NewBoolWrapper(false),
		},
	})
}
