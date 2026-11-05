/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package server

import (
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func randomTestKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("unable to generate key: %v", err)
	}
	return key
}

func testYaml(title string) string {
	return "title: " + title + "\n"
}

func newTestStore(historyKeep int) *modelStore {
	return newModelStore("threagile.yaml", historyKeep)
}

func countBackups(t *testing.T, modelFolder string) int {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(modelFolder, historyFolderName))
	if err != nil {
		if os.IsNotExist(err) {
			return 0
		}
		t.Fatalf("unable to read history folder: %v", err)
	}
	count := 0
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), backupSuffix) {
			count++
		}
	}
	return count
}

func backupNames(modelFolder string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(modelFolder, historyFolderName))
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), backupSuffix) {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

func noStagingFiles(t *testing.T, folder string) {
	t.Helper()
	entries, err := os.ReadDir(folder)
	if err != nil {
		t.Fatalf("unable to read folder: %v", err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), stagingMarker) {
			t.Fatalf("unexpected leftover staging file: %s", entry.Name())
		}
	}
}

func TestSealOpenRoundTripRejectsShortBlobs(t *testing.T) {
	key := randomTestKey(t)
	blob, err := sealModelBlob(key, []byte(testYaml("roundtrip")))
	if err != nil {
		t.Fatalf("seal failed: %v", err)
	}
	if len(blob) <= 12 {
		t.Fatalf("sealed blob suspiciously short: %d bytes", len(blob))
	}
	plain, err := openModelBlob(key, blob)
	if err != nil {
		t.Fatalf("open failed: %v", err)
	}
	if string(plain) != testYaml("roundtrip") {
		t.Fatalf("roundtrip content mismatch: %q", string(plain))
	}
	if _, err := openModelBlob(key, blob[:5]); err == nil {
		t.Fatal("expected error on truncated blob, got nil")
	}
	if _, err := parseModelBlob(key, blob[:len(blob)-3]); err == nil {
		t.Fatal("expected error on truncated ciphertext, got nil")
	}
	if _, err := parseModelBlob(key, append(append([]byte{}, blob...), []byte("garbage")...)); err == nil {
		t.Fatal("expected error on corrupted ciphertext, got nil")
	}
}

func TestCreateAndLoadReturnsRevision(t *testing.T) {
	modelFolder := t.TempDir()
	key := randomTestKey(t)
	st := newTestStore(50)

	revision, err := st.create(modelFolder, key, testYaml("v1"), "New Model Creation")
	if err != nil {
		t.Fatalf("create failed: %v", err)
	}
	if len(revision) != 64 { // sha256 hex
		t.Fatalf("unexpected revision format: %q", revision)
	}
	if countBackups(t, modelFolder) != 1 {
		t.Fatal("initial revision should be archived to history")
	}
	blob, err := os.ReadFile(filepath.Join(modelFolder, "threagile.yaml"))
	if err != nil {
		t.Fatalf("unable to read model file: %v", err)
	}
	if revisionOf(blob) != revision {
		t.Fatal("revision does not match committed file content")
	}

	loaded, err := st.load(modelFolder, key)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if loaded.Revision != revision {
		t.Fatal("loaded revision differs from created revision")
	}
	if loaded.Restored {
		t.Fatal("freshly created model must not be reported as restored")
	}
	if loaded.Model.Title != "v1" {
		t.Fatalf("unexpected model title: %q", loaded.Model.Title)
	}
}

func TestCommitChangesRevisionAndPrunesHistory(t *testing.T) {
	modelFolder := t.TempDir()
	key := randomTestKey(t)
	st := newTestStore(2) // keep only 2 backups

	rev1, err := st.create(modelFolder, key, testYaml("v1"), "New Model Creation")
	if err != nil {
		t.Fatalf("create failed: %v", err)
	}
	rev2, err := st.commit(modelFolder, key, testYaml("v2"), "Cover Update", rev1)
	if err != nil {
		t.Fatalf("commit v2 failed: %v", err)
	}
	if rev2 == rev1 {
		t.Fatal("revision must change on commit (fresh nonce + new content)")
	}
	rev3, err := st.commit(modelFolder, key, testYaml("v3"), "Cover Update", rev2)
	if err != nil {
		t.Fatalf("commit v3 failed: %v", err)
	}
	rev4, err := st.commit(modelFolder, key, testYaml("v4"), "Cover Update", rev3)
	if err != nil {
		t.Fatalf("commit v4 failed: %v", err)
	}

	loaded, err := st.load(modelFolder, key)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if loaded.Revision != rev4 || loaded.YAML != testYaml("v4") {
		t.Fatalf("current model mismatch: rev=%s title=%s", loaded.Revision, loaded.Model.Title)
	}
	if got := countBackups(t, modelFolder); got != 2 {
		t.Fatalf("history retention violated: expected 2 backups, got %d", got)
	}
	names, err := backupNames(modelFolder)
	if err != nil {
		t.Fatalf("backup names failed: %v", err)
	}
	for _, name := range names {
		if !strings.Contains(name, ".backup") {
			t.Fatalf("unexpected backup name: %s", name)
		}
	}
	if !strings.Contains(names[len(names)-1], rev4) {
		t.Fatalf("newest backup must correspond to committed revision %s, got %s", rev4, names[len(names)-1])
	}
	noStagingFiles(t, modelFolder)
}

func TestStaleCommitIsRejectedAndDoesNotConsumeHistorySlot(t *testing.T) {
	modelFolder := t.TempDir()
	key := randomTestKey(t)
	st := newTestStore(50)

	rev1, err := st.create(modelFolder, key, testYaml("v1"), "New Model Creation")
	if err != nil {
		t.Fatalf("create failed: %v", err)
	}
	rev2, err := st.commit(modelFolder, key, testYaml("v2"), "Cover Update", rev1)
	if err != nil {
		t.Fatalf("commit v2 failed: %v", err)
	}
	backupsBefore := countBackups(t, modelFolder)

	// another client still holds rev1 and tries to commit on top of it
	_, err = st.commit(modelFolder, key, testYaml("stale"), "Cover Update", rev1)
	if err != ErrStaleRevision {
		t.Fatalf("expected ErrStaleRevision, got %v", err)
	}
	if got := countBackups(t, modelFolder); got != backupsBefore {
		t.Fatalf("failed commit consumed a history retention slot: before=%d after=%d", backupsBefore, got)
	}

	// the newer version must be untouched
	loaded, err := st.load(modelFolder, key)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if loaded.Revision != rev2 || loaded.YAML != testYaml("v2") {
		t.Fatal("stale edit overwrote the newer committed version")
	}
	blob, err := os.ReadFile(filepath.Join(modelFolder, "threagile.yaml"))
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if revisionOf(blob) != rev2 {
		t.Fatal("model file revision changed despite rejected commit")
	}
	noStagingFiles(t, modelFolder)
}

func TestRecoverFromShortWriteAndInterruptedProcess(t *testing.T) {
	modelFolder := t.TempDir()
	key := randomTestKey(t)
	st := newTestStore(50)

	rev1, err := st.create(modelFolder, key, testYaml("v1"), "New Model Creation")
	if err != nil {
		t.Fatalf("create failed: %v", err)
	}
	rev2, err := st.commit(modelFolder, key, testYaml("v2"), "Cover Update", rev1)
	if err != nil {
		t.Fatalf("commit v2 failed: %v", err)
	}

	// simulate the old writer being interrupted: primary file truncated to a few bytes
	target := filepath.Join(modelFolder, "threagile.yaml")
	if err := os.WriteFile(target, []byte{0x01, 0x02, 0x03, 0x04, 0x05}, 0600); err != nil {
		t.Fatalf("unable to corrupt model: %v", err)
	}
	// plus a staging file from the interrupted write
	staging := filepath.Join(modelFolder, ".threagile.yaml"+stagingMarker+"interrupted")
	if err := os.WriteFile(staging, []byte("partial"), 0600); err != nil {
		t.Fatalf("unable to create staging leftover: %v", err)
	}

	loaded, err := st.load(modelFolder, key)
	if err != nil {
		t.Fatalf("recovery failed: %v", err)
	}
	if !loaded.Restored {
		t.Fatal("expected model to be restored from history")
	}
	if loaded.Revision != rev2 {
		t.Fatalf("recovered wrong revision: got %s want %s", loaded.Revision, rev2)
	}
	if loaded.YAML != testYaml("v2") {
		t.Fatalf("recovered content mismatch: %q", loaded.YAML)
	}
	// restored file is itself complete and decryptable again
	blob, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read restored file failed: %v", err)
	}
	if revisionOf(blob) != rev2 {
		t.Fatal("restored file revision mismatch")
	}
	if _, err := parseModelBlob(key, blob); err != nil {
		t.Fatalf("restored model is not decryptable/parsable: %v", err)
	}
	noStagingFiles(t, modelFolder)

	// and analysis can continue: the recovered model supports a fresh commit on top
	rev3, err := st.commit(modelFolder, key, testYaml("v3"), "Cover Update", rev2)
	if err != nil {
		t.Fatalf("commit after recovery failed: %v", err)
	}
	loaded2, err := st.load(modelFolder, key)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if loaded2.Revision != rev3 || loaded2.Model.Title != "v3" {
		t.Fatal("recovered model could not be re-analyzed/committed")
	}
}

func TestRecoverFromMissingPrimaryFile(t *testing.T) {
	modelFolder := t.TempDir()
	key := randomTestKey(t)
	st := newTestStore(50)

	rev1, err := st.create(modelFolder, key, testYaml("v1"), "New Model Creation")
	if err != nil {
		t.Fatalf("create failed: %v", err)
	}
	if err := os.Remove(filepath.Join(modelFolder, "threagile.yaml")); err != nil {
		t.Fatalf("remove failed: %v", err)
	}
	loaded, err := st.load(modelFolder, key)
	if err != nil {
		t.Fatalf("recovery from missing file failed: %v", err)
	}
	if !loaded.Restored || loaded.Revision != rev1 {
		t.Fatalf("unexpected recovery result: restored=%v rev=%s", loaded.Restored, loaded.Revision)
	}
}

func TestLegacyCiphertextIsReadableAndCommittable(t *testing.T) {
	modelFolder := t.TempDir()
	if err := os.MkdirAll(modelFolder, 0700); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	key := randomTestKey(t)
	st := newTestStore(50)

	// emulate a file written by the old server code: plain nonce+ciphertext blob, no revision metadata at all
	legacyBlob, err := sealModelBlob(key, []byte(testYaml("legacy")))
	if err != nil {
		t.Fatalf("seal failed: %v", err)
	}
	target := filepath.Join(modelFolder, "threagile.yaml")
	if err := os.WriteFile(target, legacyBlob, 0644); err != nil { // old code used os.Create perms
		t.Fatalf("write legacy file failed: %v", err)
	}

	loaded, err := st.load(modelFolder, key)
	if err != nil {
		t.Fatalf("reading legacy ciphertext failed: %v", err)
	}
	if loaded.Revision != revisionOf(legacyBlob) {
		t.Fatal("revision of legacy file mismatch")
	}
	if loaded.Model.Title != "legacy" {
		t.Fatalf("unexpected title: %q", loaded.Model.Title)
	}

	// a client editing based on the legacy revision can commit normally
	rev2, err := st.commit(modelFolder, key, testYaml("modern"), "Cover Update", loaded.Revision)
	if err != nil {
		t.Fatalf("commit on top of legacy file failed: %v", err)
	}
	loaded2, err := st.load(modelFolder, key)
	if err != nil {
		t.Fatalf("reload failed: %v", err)
	}
	if loaded2.Revision != rev2 || loaded2.Model.Title != "modern" {
		t.Fatal("commit on legacy file did not persist correctly")
	}
}

func TestRecoveryUnderstandsLegacyBackupNamingAndSkipsCorruptBackups(t *testing.T) {
	modelFolder := t.TempDir()
	key := randomTestKey(t)
	st := newTestStore(50)
	historyDir := filepath.Join(modelFolder, historyFolderName)
	if err := os.MkdirAll(historyDir, 0700); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}

	validBlob, err := sealModelBlob(key, []byte(testYaml("old-style")))
	if err != nil {
		t.Fatalf("seal failed: %v", err)
	}
	// old history naming: "2006-01-02 15:04:05 Reason.backup"
	if err := os.WriteFile(filepath.Join(historyDir, "2020-01-02 15:04:05 Old Style.backup"), validBlob, 0400); err != nil {
		t.Fatalf("write old-style backup failed: %v", err)
	}
	// a newer, corrupt backup must be skipped
	if err := os.WriteFile(filepath.Join(historyDir, "20261105T101010.000000000Z-Cover_Update-"+revisionOf([]byte("x"))+backupSuffix), []byte("not a blob"), 0400); err != nil {
		t.Fatalf("write corrupt backup failed: %v", err)
	}
	// primary file corrupt
	if err := os.WriteFile(filepath.Join(modelFolder, "threagile.yaml"), []byte("short"), 0600); err != nil {
		t.Fatalf("corrupt model failed: %v", err)
	}

	loaded, err := st.load(modelFolder, key)
	if err != nil {
		t.Fatalf("recovery failed: %v", err)
	}
	if !loaded.Restored || loaded.Model.Title != "old-style" {
		t.Fatalf("did not fall back to valid legacy backup: restored=%v title=%s", loaded.Restored, loaded.Model.Title)
	}
	if loaded.Revision != revisionOf(validBlob) {
		t.Fatal("recovered revision mismatch")
	}
}

func TestUnrecoverableModel(t *testing.T) {
	modelFolder := t.TempDir()
	key := randomTestKey(t)
	st := newTestStore(50)

	if err := os.WriteFile(filepath.Join(modelFolder, "threagile.yaml"), []byte("broken"), 0600); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if _, err := st.load(modelFolder, key); !errors.Is(err, ErrModelNotRecoverable) {
		t.Fatalf("expected ErrModelNotRecoverable, got %v", err)
	}
}

func TestCreateRefusesToOverwriteExistingModel(t *testing.T) {
	modelFolder := t.TempDir()
	key := randomTestKey(t)
	st := newTestStore(50)

	if _, err := st.create(modelFolder, key, testYaml("v1"), "New Model Creation"); err != nil {
		t.Fatalf("create failed: %v", err)
	}
	if _, err := st.create(modelFolder, key, testYaml("v2"), "New Model Creation"); err != ErrModelAlreadyExists {
		t.Fatalf("expected ErrModelAlreadyExists, got %v", err)
	}
}

// The old lock implementation deleted a folder mutex on unlock even while
// another goroutine was blocked on it, which allowed a third goroutine to
// create a fresh mutex and enter the same critical section concurrently.
func TestFolderLockSerializesWaitersWhenUnlocked(t *testing.T) {
	s := &server{locksByFolderName: make(map[string]*folderLock)}

	s.lockFolder("model")
	waiterEntered := make(chan struct{})
	go func() {
		s.lockFolder("model")
		close(waiterEntered)
		s.unlockFolder("model")
	}()

	select {
	case <-waiterEntered:
		t.Fatal("waiting goroutine entered the critical section while the lock was held")
	case <-time.After(25 * time.Millisecond):
	}

	s.unlockFolder("model")
	select {
	case <-waiterEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("waiting goroutine never acquired the lock after unlock")
	}

	// after both holders are gone the entry may be removed, but lock/unlock must still work
	deadline := time.After(2 * time.Second)
	for {
		s.globalLock.Lock()
		_, present := s.locksByFolderName["model"]
		s.globalLock.Unlock()
		if !present {
			break
		}
		select {
		case <-deadline:
			t.Fatal("stale lock entry was never removed after last holder released it")
		case <-time.After(time.Millisecond):
		}
	}
	s.lockFolder("model")
	s.unlockFolder("model")
}

func TestFolderLockStress(t *testing.T) {
	s := &server{locksByFolderName: make(map[string]*folderLock)}
	const goroutines = 40
	const iterations = 50
	var counter int64
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				s.lockFolder("model")
				read := counter
				counter = read + 1
				s.unlockFolder("model")
			}
		}()
	}
	wg.Wait()
	if counter != int64(goroutines*iterations) {
		t.Fatalf("lost updates: got %d, expected %d", counter, goroutines*iterations)
	}
	s.globalLock.Lock()
	remaining := len(s.locksByFolderName)
	s.globalLock.Unlock()
	if remaining != 0 {
		t.Fatalf("lock map leaked %d entries", remaining)
	}
}
