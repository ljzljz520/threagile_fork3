/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package server

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/threagile/threagile/pkg/input"
)

// Revision-based, atomic model storage.
//
// On-disk blob format (unchanged, so old ciphertext stays readable):
//
//	nonce(12 bytes) || AES-256-GCM(gzip(yaml text))
//
// The revision of a stored model is the SHA-256 hex of the complete blob
// bytes of the committed file. Clients receive it on reads (ETag /
// X-Revision header) and must echo it via If-Match on updates, which gives
// optimistic concurrency control on top of the in-process folder locks.

var (
	// ErrStaleRevision is returned when a commit is based on a revision that
	// is no longer the current one (someone else committed in between).
	ErrStaleRevision = errors.New("model revision conflict: the edit is based on an outdated revision")
	// ErrModelNotRecoverable is returned when neither the model file nor any
	// history backup can be decrypted and parsed.
	ErrModelNotRecoverable = errors.New("model is not readable and no valid history backup is available")
	// ErrModelAlreadyExists is returned on initial creation when a model file is already present.
	ErrModelAlreadyExists = errors.New("model already exists")
	// ErrInvalidModelBlob is returned when a freshly sealed blob fails its own round-trip verification.
	ErrInvalidModelBlob = errors.New("sealed model blob failed verification")
)

const (
	historyFolderName = "history"
	backupSuffix      = ".backup"
	stagingMarker     = ".staging-"
	modelFileMode     = 0600
	backupFileMode    = 0400
)

type modelStore struct {
	inputFileName string
	historyKeep   int
}

type loadedModel struct {
	Model    input.Model
	YAML     string
	Revision string
	// Restored is true when the primary model file was unreadable/missing and
	// the model had to be recovered from a history backup.
	Restored bool
}

func newModelStore(inputFileName string, historyKeep int) *modelStore {
	return &modelStore{
		inputFileName: filepath.Base(inputFileName),
		historyKeep:   historyKeep,
	}
}

func (st *modelStore) modelFile(modelFolder string) string {
	return filepath.Join(modelFolder, st.inputFileName)
}

func (st *modelStore) historyFolder(modelFolder string) string {
	return filepath.Join(modelFolder, historyFolderName)
}

// revisionOf computes the opaque revision identifier of a committed blob.
func revisionOf(blob []byte) string {
	sum := sha256.Sum256(blob)
	return hex.EncodeToString(sum[:])
}

// sealModelBlob compresses, encrypts and prepends a fresh random nonce. Every
// write error is checked so that callers never end up sealing partial data.
func sealModelBlob(key []byte, plaintext []byte) ([]byte, error) {
	var compressed bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressed)
	if _, err := gzipWriter.Write(plaintext); err != nil {
		return nil, fmt.Errorf("unable to compress model: %w", err)
	}
	if err := gzipWriter.Close(); err != nil {
		return nil, fmt.Errorf("unable to compress model: %w", err)
	}
	block, err := aes.NewCipher(generateKeyFromAlreadyStrongRandomInput(key))
	if err != nil {
		return nil, fmt.Errorf("unable to init cipher: %w", err)
	}
	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("unable to init cipher: %w", err)
	}
	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, aesGcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("unable to generate nonce: %w", err)
	}
	ciphertext := aesGcm.Seal(nil, nonce, compressed.Bytes(), nil) // #nosec G407 // nonce is freshly generated random
	blob := make([]byte, 0, len(nonce)+len(ciphertext))
	blob = append(blob, nonce...)
	blob = append(blob, ciphertext...)
	return blob, nil
}

// openModelBlob decrypts, decompresses and fully reads a stored blob. It works
// on any blob written by the old or the new writer, because the on-disk format
// is unchanged. Short/truncated blobs are reported instead of causing panics.
func openModelBlob(key []byte, blob []byte) ([]byte, error) {
	block, err := aes.NewCipher(generateKeyFromAlreadyStrongRandomInput(key))
	if err != nil {
		return nil, fmt.Errorf("unable to init cipher: %w", err)
	}
	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("unable to init cipher: %w", err)
	}
	nonceSize := aesGcm.NonceSize()
	if len(blob) < nonceSize+aesGcm.Overhead() {
		return nil, fmt.Errorf("ciphertext too short (%d bytes)", len(blob))
	}
	plaintext, err := aesGcm.Open(nil, blob[:nonceSize], blob[nonceSize:], nil) // #nosec G407 // nonce is read from the file for decryption
	if err != nil {
		return nil, fmt.Errorf("unable to decrypt: %w", err)
	}
	reader, err := gzip.NewReader(bytes.NewReader(plaintext))
	if err != nil {
		return nil, fmt.Errorf("unable to decompress: %w", err)
	}
	decompressed, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("unable to decompress: %w", err)
	}
	if err := reader.Close(); err != nil {
		return nil, fmt.Errorf("unable to decompress: %w", err)
	}
	return decompressed, nil
}

// parseModelBlob verifies a complete decrypt -> decompress -> YAML parse chain.
// Only blobs passing this are considered "complete, decryptable and
// re-analyzable".
func parseModelBlob(key []byte, blob []byte) ([]byte, error) {
	yamlBytes, err := openModelBlob(key, blob)
	if err != nil {
		return nil, err
	}
	modelInput := new(input.Model).Defaults()
	if err := yaml.Unmarshal(yamlBytes, modelInput); err != nil {
		return nil, fmt.Errorf("unable to parse model yaml: %w", err)
	}
	return yamlBytes, nil
}

// sealAndVerify seals the yaml text and immediately proves that the resulting
// blob fully round-trips back to the exact same yaml text and parses.
func (st *modelStore) sealAndVerify(key []byte, yamlText []byte) ([]byte, error) {
	blob, err := sealModelBlob(key, yamlText)
	if err != nil {
		return nil, err
	}
	roundTripped, err := openModelBlob(key, blob)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidModelBlob, err)
	}
	if !bytes.Equal(roundTripped, yamlText) {
		return nil, fmt.Errorf("%w: decrypted content does not match", ErrInvalidModelBlob)
	}
	modelInput := new(input.Model).Defaults()
	if err := yaml.Unmarshal(roundTripped, modelInput); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidModelBlob, err)
	}
	return blob, nil
}

// writeFileAtomic writes data to a hidden staging file in the same directory,
// fsyncs it, verifies its size and only then atomically renames it over the
// destination, followed by an fsync of the directory. A crash or a short write
// at any point therefore leaves either the old or the new complete file, never
// a truncated one.
func writeFileAtomic(path string, data []byte, perm os.FileMode) (err error) {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	staging, err := os.CreateTemp(dir, "."+base+stagingMarker+"*")
	if err != nil {
		return err
	}
	stagingName := staging.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(stagingName)
		}
	}()
	if err = staging.Chmod(perm); err != nil {
		_ = staging.Close()
		return err
	}
	written, err := staging.Write(data)
	if err == nil && written != len(data) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = staging.Sync()
	}
	if closeErr := staging.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	info, err := os.Stat(stagingName)
	if err != nil {
		return err
	}
	if info.Size() != int64(len(data)) {
		return fmt.Errorf("staged file size mismatch: got %d bytes, expected %d bytes", info.Size(), len(data))
	}
	if err = os.Rename(stagingName, path); err != nil {
		return err
	}
	committed = true
	return syncDirectory(dir)
}

func syncDirectory(dir string) error {
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = directory.Sync()
	if closeErr := directory.Close(); err == nil {
		err = closeErr
	}
	return err
}

// sweepStagingFiles removes leftover staging files from an interrupted process.
func sweepStagingFiles(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if strings.Contains(entry.Name(), stagingMarker) {
			_ = os.Remove(filepath.Join(dir, entry.Name()))
		}
	}
}

// load reads the current model. When the primary file is missing, short,
// partially written or otherwise undecryptable/unparsable, it transparently
// restores the newest valid history backup (old ciphertext backups included).
func (st *modelStore) load(modelFolder string, key []byte) (*loadedModel, error) {
	target := st.modelFile(modelFolder)
	blob, err := os.ReadFile(filepath.Clean(target))
	if err == nil {
		if yamlBytes, parseErr := parseModelBlob(key, blob); parseErr == nil {
			return st.asLoadedModel(blob, yamlBytes, false), nil
		} else {
			log.Printf("model file %q is unreadable (%v); trying to recover from history", target, parseErr)
		}
	} else {
		log.Printf("model file %q is missing (%v); trying to recover from history", target, err)
	}
	return st.recover(modelFolder, key)
}

func (st *modelStore) asLoadedModel(blob, yamlBytes []byte, restored bool) *loadedModel {
	modelInput := new(input.Model).Defaults()
	_ = yaml.Unmarshal(yamlBytes, modelInput) // already validated by parseModelBlob
	return &loadedModel{
		Model:    *modelInput,
		YAML:     string(yamlBytes),
		Revision: revisionOf(blob),
		Restored: restored,
	}
}

// recover restores the newest valid history backup atomically.
func (st *modelStore) recover(modelFolder string, key []byte) (*loadedModel, error) {
	sweepStagingFiles(modelFolder)
	historyDir := st.historyFolder(modelFolder)
	entries, err := os.ReadDir(filepath.Clean(historyDir))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrModelNotRecoverable, err)
	}
	backups := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), backupSuffix) {
			backups = append(backups, entry.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(backups))) // newest name first (names are timestamp-first)
	target := st.modelFile(modelFolder)
	for _, backupName := range backups {
		backupPath := filepath.Join(historyDir, backupName)
		blob, readErr := os.ReadFile(filepath.Clean(backupPath))
		if readErr != nil {
			continue
		}
		yamlBytes, parseErr := parseModelBlob(key, blob)
		if parseErr != nil {
			log.Printf("skipping unreadable history backup %q: %v", backupName, parseErr)
			continue
		}
		if restoreErr := writeFileAtomic(target, blob, modelFileMode); restoreErr != nil {
			return nil, fmt.Errorf("unable to restore model from backup %q: %w", backupName, restoreErr)
		}
		log.Printf("recovered model from history backup %q", backupName)
		return st.asLoadedModel(blob, yamlBytes, true), nil
	}
	return nil, ErrModelNotRecoverable
}

// currentOrRecoveredBlob returns the bytes of the current model, triggering a
// recovery from history when the primary file is damaged.
func (st *modelStore) currentOrRecoveredBlob(modelFolder string, key []byte) ([]byte, error) {
	target := st.modelFile(modelFolder)
	blob, err := os.ReadFile(filepath.Clean(target))
	if err == nil {
		if _, parseErr := parseModelBlob(key, blob); parseErr == nil {
			return blob, nil
		}
	}
	if _, recoverErr := st.recover(modelFolder, key); recoverErr != nil {
		return nil, recoverErr
	}
	return os.ReadFile(filepath.Clean(target))
}

// create seals and atomically commits the very first revision of a model. It
// refuses to overwrite an existing file.
func (st *modelStore) create(modelFolder string, key []byte, yamlText, reason string) (newRevision string, err error) {
	target := st.modelFile(modelFolder)
	if _, err := os.Stat(filepath.Clean(target)); err == nil {
		return "", ErrModelAlreadyExists
	} else if !os.IsNotExist(err) {
		return "", err
	}
	blob, err := st.sealAndVerify(key, []byte(yamlText))
	if err != nil {
		return "", err
	}
	sweepStagingFiles(modelFolder)
	if err := writeFileAtomic(target, blob, modelFileMode); err != nil {
		return "", err
	}
	newRevision = revisionOf(blob)
	if archiveErr := st.archive(modelFolder, reason, blob, newRevision); archiveErr != nil {
		log.Printf("warning: unable to archive initial revision %s to history: %v", newRevision, archiveErr)
	}
	return newRevision, nil
}

// commit seals and atomically commits a new revision, but only when the current
// revision still matches expectedRevision (optimistic concurrency control).
// History is archived strictly after the commit succeeded, so failed commits
// never consume a history retention slot.
func (st *modelStore) commit(modelFolder string, key []byte, yamlText, reason, expectedRevision string) (newRevision string, err error) {
	currentBlob, err := st.currentOrRecoveredBlob(modelFolder, key)
	if err != nil {
		return "", err
	}
	if revisionOf(currentBlob) != expectedRevision {
		return "", ErrStaleRevision
	}
	blob, err := st.sealAndVerify(key, []byte(yamlText))
	if err != nil {
		return "", err
	}
	sweepStagingFiles(modelFolder)
	target := st.modelFile(modelFolder)
	if err := writeFileAtomic(target, blob, modelFileMode); err != nil {
		return "", err
	}
	newRevision = revisionOf(blob)
	if archiveErr := st.archive(modelFolder, reason, blob, newRevision); archiveErr != nil {
		// The model itself is safely committed; history archival must not make
		// the client retry (and then run into a stale revision conflict).
		log.Printf("warning: unable to archive committed revision %s to history: %v", newRevision, archiveErr)
	}
	return newRevision, nil
}

// archive stores an exact, hash-verified copy of a successfully committed blob
// in the history folder and afterwards prunes old entries. Only successfully
// committed revisions ever reach this point.
func (st *modelStore) archive(modelFolder, reason string, blob []byte, revision string) error {
	historyDir := st.historyFolder(modelFolder)
	if err := os.MkdirAll(filepath.Clean(historyDir), 0700); err != nil {
		return err
	}
	sweepStagingFiles(historyDir)
	backupName := time.Now().UTC().Format("20060102T150405.000000000Z") + "-" + sanitizeHistoryReason(reason) + "-" + revision + backupSuffix
	backupPath := filepath.Join(historyDir, backupName)
	if err := writeFileAtomic(backupPath, blob, backupFileMode); err != nil {
		return err
	}
	archived, err := os.ReadFile(filepath.Clean(backupPath))
	if err != nil {
		return err
	}
	if revisionOf(archived) != revision {
		_ = os.Remove(backupPath)
		return fmt.Errorf("archived history backup does not match committed revision %s", revision)
	}
	return st.pruneHistory(historyDir)
}

func (st *modelStore) pruneHistory(historyDir string) error {
	if st.historyKeep <= 0 {
		return nil
	}
	entries, err := os.ReadDir(filepath.Clean(historyDir))
	if err != nil {
		return err
	}
	backups := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), backupSuffix) {
			backups = append(backups, entry.Name())
		}
	}
	if len(backups) <= st.historyKeep {
		return nil
	}
	sort.Strings(backups) // oldest names first (names are timestamp-first)
	requiredToDelete := len(backups) - st.historyKeep
	for _, backupName := range backups {
		if err := os.Remove(filepath.Join(historyDir, backupName)); err != nil {
			return err
		}
		requiredToDelete--
		if requiredToDelete <= 0 {
			break
		}
	}
	return nil
}

func sanitizeHistoryReason(reason string) string {
	safe := strings.TrimSpace(filepath.Base(reason))
	replacer := strings.NewReplacer(
		" ", "_",
		"/", "_",
		"\\", "_",
		":", "_",
		"\t", "_",
		"\n", "_",
	)
	safe = replacer.Replace(safe)
	safe = strings.Trim(safe, ".")
	if safe == "" || safe == "." || safe == string(os.PathSeparator) {
		return "update"
	}
	if len(safe) > 64 {
		safe = safe[:64]
	}
	return safe
}
