package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tobischo/gokeepasslib/v3"
	w "github.com/tobischo/gokeepasslib/v3/wrappers"
)

func TestEnumerateTitle(t *testing.T) {
	group := gokeepasslib.NewGroup()
	group.Entries = []gokeepasslib.Entry{
		newEntry("Email", "one"),
		newEntry("Email (2)", "two"),
	}

	got := enumerateTitle(&group, "Email")
	if got != "Email (3)" {
		t.Fatalf("expected Email (3), got %q", got)
	}
}

func TestMergeGroupsSkipsExactDuplicate(t *testing.T) {
	target := gokeepasslib.NewGroup()
	target.Entries = []gokeepasslib.Entry{newEntry("Email", "same")}

	source := gokeepasslib.NewGroup()
	source.Entries = []gokeepasslib.Entry{newEntry("Email", "same")}

	mergeGroups(&target, &source)

	if len(target.Entries) != 1 {
		t.Fatalf("expected duplicate entry to be skipped, got %d entries", len(target.Entries))
	}
}

func TestMergeGroupsEnumeratesConflictingDuplicate(t *testing.T) {
	target := gokeepasslib.NewGroup()
	target.Entries = []gokeepasslib.Entry{newEntry("Email", "old-password")}

	source := gokeepasslib.NewGroup()
	source.Entries = []gokeepasslib.Entry{newEntry("Email", "new-password")}

	mergeGroups(&target, &source)

	if len(target.Entries) != 2 {
		t.Fatalf("expected conflicting entry to be retained, got %d entries", len(target.Entries))
	}
	if got := target.Entries[1].GetTitle(); got != "Email (2)" {
		t.Fatalf("expected enumerated title Email (2), got %q", got)
	}
}

func TestMergeGroupsMergesMatchingSubgroups(t *testing.T) {
	target := gokeepasslib.NewGroup()
	target.Name = "Root"
	target.Groups = []gokeepasslib.Group{{
		Name:    "Work",
		Entries: []gokeepasslib.Entry{newEntry("VPN", "one")},
	}}

	source := gokeepasslib.NewGroup()
	source.Name = "Root"
	source.Groups = []gokeepasslib.Group{{
		Name:    "Work",
		Entries: []gokeepasslib.Entry{newEntry("GitHub", "two")},
	}}

	mergeGroups(&target, &source)

	work := findGroup(&target, "Work")
	if work == nil {
		t.Fatal("expected Work subgroup to exist")
	}
	if len(work.Entries) != 2 {
		t.Fatalf("expected merged subgroup to contain 2 entries, got %d", len(work.Entries))
	}
}

func TestRunMergesSyntheticKeePassDatabases(t *testing.T) {
	tempDir := t.TempDir()
	inputDir := filepath.Join(tempDir, "input")
	outputPath := filepath.Join(tempDir, "merged.kdbx")
	password := "correct horse battery staple"

	if err := os.Mkdir(inputDir, 0o755); err != nil {
		t.Fatal(err)
	}

	writeTestDatabase(t, filepath.Join(inputDir, "one.kdbx"), password, []gokeepasslib.Group{
		{
			Name: "Personal",
			Entries: []gokeepasslib.Entry{
				newEntry("Email", "same-password"),
				newEntry("Bank", "bank-password"),
			},
		},
	})
	writeTestDatabase(t, filepath.Join(inputDir, "two.kdbx"), password, []gokeepasslib.Group{
		{
			Name: "Personal",
			Entries: []gokeepasslib.Entry{
				newEntry("Email", "same-password"),
				newEntry("Bank", "changed-password"),
			},
		},
		{
			Name:    "Work",
			Entries: []gokeepasslib.Entry{newEntry("VPN", "vpn-password")},
		},
	})

	var stdout bytes.Buffer
	err := run(options{
		InputDir: inputDir,
		Output:   outputPath,
		RootName: "Merged Test",
	}, strings.NewReader(password+"\n\n"), &stdout)
	if err != nil {
		t.Fatal(err)
	}

	mergedDB, err := openDatabase(outputPath, password)
	if err != nil {
		t.Fatal(err)
	}

	root := &mergedDB.Content.Root.Groups[0]
	if root.Name != "Merged Test" {
		t.Fatalf("expected root name Merged Test, got %q", root.Name)
	}

	personal := findGroup(root, "Personal")
	if personal == nil {
		t.Fatal("expected Personal group")
	}
	if findEntry(personal, "Email") == nil {
		t.Fatal("expected Email entry")
	}
	if findEntry(personal, "Bank") == nil {
		t.Fatal("expected Bank entry")
	}
	if findEntry(personal, "Bank (2)") == nil {
		t.Fatal("expected conflicting Bank entry to be retained as Bank (2)")
	}
	if got := len(personal.Entries); got != 3 {
		t.Fatalf("expected 3 Personal entries after duplicate handling, got %d", got)
	}

	work := findGroup(root, "Work")
	if work == nil || findEntry(work, "VPN") == nil {
		t.Fatal("expected Work/VPN entry")
	}
}

func TestRunCanUseDifferentOutputPassword(t *testing.T) {
	tempDir := t.TempDir()
	inputDir := filepath.Join(tempDir, "input")
	outputPath := filepath.Join(tempDir, "merged.kdbx")
	inputPassword := "input password"
	outputPassword := "output password"

	if err := os.Mkdir(inputDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestDatabase(t, filepath.Join(inputDir, "one.kdbx"), inputPassword, []gokeepasslib.Group{
		{
			Name:    "Personal",
			Entries: []gokeepasslib.Entry{newEntry("Email", "entry-password")},
		},
	})

	var stdout bytes.Buffer
	err := run(options{
		InputDir: inputDir,
		Output:   outputPath,
		RootName: "Merged Test",
	}, strings.NewReader(inputPassword+"\n"+outputPassword+"\n"+outputPassword+"\n"), &stdout)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := openDatabase(outputPath, inputPassword); err == nil {
		t.Fatal("expected input password not to open output database")
	}
	if _, err := openDatabase(outputPath, outputPassword); err != nil {
		t.Fatalf("expected output password to open output database: %v", err)
	}
}

func TestRunRejectsMismatchedOutputPasswordConfirmation(t *testing.T) {
	tempDir := t.TempDir()
	inputDir := filepath.Join(tempDir, "input")
	outputPath := filepath.Join(tempDir, "merged.kdbx")
	inputPassword := "input password"

	if err := os.Mkdir(inputDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestDatabase(t, filepath.Join(inputDir, "one.kdbx"), inputPassword, []gokeepasslib.Group{
		{
			Name:    "Personal",
			Entries: []gokeepasslib.Entry{newEntry("Email", "entry-password")},
		},
	})

	var stdout bytes.Buffer
	err := run(options{
		InputDir: inputDir,
		Output:   outputPath,
	}, strings.NewReader(inputPassword+"\nfirst output\nsecond output\n"), &stdout)
	if err == nil {
		t.Fatal("expected mismatched output password confirmation to fail")
	}
	if !strings.Contains(err.Error(), "output vault passwords do not match") {
		t.Fatalf("expected password mismatch error, got %v", err)
	}
}

func TestRunStopsWhenInputCannotBeOpened(t *testing.T) {
	tempDir := t.TempDir()
	inputDir := filepath.Join(tempDir, "input")
	outputPath := filepath.Join(tempDir, "merged.kdbx")

	if err := os.Mkdir(inputDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestDatabase(t, filepath.Join(inputDir, "one.kdbx"), "actual input password", []gokeepasslib.Group{
		{
			Name:    "Personal",
			Entries: []gokeepasslib.Entry{newEntry("Email", "entry-password")},
		},
	})

	var stdout bytes.Buffer
	err := run(options{
		InputDir: inputDir,
		Output:   outputPath,
	}, strings.NewReader("wrong input password\n\n"), &stdout)
	if err == nil {
		t.Fatal("expected unreadable input database to fail")
	}
	if !strings.Contains(err.Error(), "opening") {
		t.Fatalf("expected opening error, got %v", err)
	}
	if _, statErr := os.Stat(outputPath); !os.IsNotExist(statErr) {
		t.Fatalf("expected no output database to be written, stat error: %v", statErr)
	}
}

func newEntry(title, password string) gokeepasslib.Entry {
	return gokeepasslib.Entry{
		Values: []gokeepasslib.ValueData{
			{
				Key: "Title",
				Value: gokeepasslib.V{
					Content:   title,
					Protected: w.NewBoolWrapper(false),
				},
			},
			{
				Key: "Password",
				Value: gokeepasslib.V{
					Content:   password,
					Protected: w.NewBoolWrapper(true),
				},
			},
		},
	}
}

func writeTestDatabase(t *testing.T, path, password string, groups []gokeepasslib.Group) {
	t.Helper()

	db := newDatabase(password, "Root")
	db.Content.Root.Groups[0].Groups = groups

	if err := writeDatabase(path, db); err != nil {
		t.Fatal(err)
	}
}
