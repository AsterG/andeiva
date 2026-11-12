package configpoc

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

type v2LegacyBinding struct {
	Source       string `json:"source"`
	Actor        string `json:"actor"`
	Subject      string `json:"subject"`
	ReceiptIndex string `json:"receipt_index"`
}
type v2LegacyImage struct {
	Domain       string             `json:"domain"`
	Source       string             `json:"source"`
	Tip          string             `json:"tip"`
	Sequence     uint64             `json:"sequence,string"`
	Projection   uint64             `json:"projection,string"`
	Snapshot     Snapshot           `json:"snapshot"`
	Receipts     map[string]receipt `json:"receipts"`
	ReceiptIndex string             `json:"receipt_index"`
	Records      []string           `json:"records"`
}
type v2ComponentReference struct {
	Schema   int    `json:"config_schema"`
	Revision string `json:"revision"`
}
type v2Composite struct {
	Schema        int                   `json:"schema_version"`
	Firewall      v2ComponentReference  `json:"firewall"`
	LocalServices v2ComponentReference  `json:"local_services"`
	Network       *v2ComponentReference `json:"network"`
}
type v2Migration struct {
	Format        string            `json:"format"`
	Status        string            `json:"status"`
	Firewall      v2LegacyImage     `json:"firewall"`
	LocalServices v2LegacyImage     `json:"local_services"`
	Bindings      []v2LegacyBinding `json:"bindings"`
	Running       v2Composite       `json:"running_target"`
	Startup       v2Composite       `json:"startup"`
}

// inspectLegacyV2 never invokes openStore/Service.Open: both can mutate an old
// layout. The caller holds its existing lock. Pending staging is refused,
// retained and left to the old authorized recovery path.
func inspectLegacyV2(area *os.Root, domain string, destination *v2Store) (v2LegacyImage, error) {
	image := v2LegacyImage{Domain: domain, Records: []string{}}
	if area == nil || (domain != "firewall" && domain != "local_services") {
		return image, errV2Invalid
	}
	before, err := area.Stat(".")
	if err != nil || !before.IsDir() || before.Mode().Perm() != 0700 || !owned(before) {
		return image, errV2Unavailable
	}
	dir, err := area.Open(".")
	if err != nil {
		return image, errV2Unavailable
	}
	entries, readErr := dir.ReadDir(2052)
	closeErr := dir.Close()
	if (readErr != nil && readErr != io.EOF) || closeErr != nil || len(entries) > 2051 {
		return image, errV2Unavailable
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	owner, err := checkpointRead(area, stagingRegistration, maxMarkerBytes)
	if err != nil {
		return image, errV2Unavailable
	}
	var marker stageOwner
	if checkpointDecode(owner, &marker) != nil {
		return image, errV2Unavailable
	}
	legacy := &fileStore{dir: area.Name(), owner: owner, limit: 2048}
	payload, err := legacy.validateStaging(area)
	if err != nil || payload != nil {
		return image, errV2Unavailable
	}
	image.Source = checkpointDigest(owner)
	previous := ""
	total := int64(0)
	var latest durableState
	for _, entry := range entries {
		if entry.Name() == "state.lock" || entry.Name() == stagingRegistration || entry.Name() == stagingDirectory {
			continue
		}
		sequence := image.Sequence + 1
		if entry.Name() != fmt.Sprintf("%08d.json", sequence) {
			return image, errV2Unavailable
		}
		info, e := area.Lstat(entry.Name())
		if e != nil || !regularOwned(info, maxRecordBytes) {
			return image, errV2Unavailable
		}
		total += info.Size()
		if total > maxJournalBytes || sequence > 2048 {
			return image, errV2Unavailable
		}
		data, _, e := readRecordData(area, sequence, info)
		if e != nil {
			return image, errV2Unavailable
		}
		record, e := decodeRecord(data, sequence, previous, "")
		if e != nil {
			return image, errV2Unavailable
		}
		// Preserve exact original record bytes and complete protected audit in
		// immutable objects; component canonical hashes are never rewritten.
		hash := checkpointDigest(data)
		if destination != nil {
			hash, e = destination.object(struct {
				Format string `json:"format"`
				Bytes  []byte `json:"bytes"`
			}{v2Format, data})
			if e != nil {
				return image, e
			}
		}
		image.Records = append(image.Records, hash)
		image.Sequence = sequence
		previous = record.Hash
		latest = record.State
	}
	if image.Sequence == 0 || latest.Intent != nil || latest.Snapshot.Candidate != nil || latest.Snapshot.Pending != nil || latest.Snapshot.RecoveryRequired {
		return image, errV2Invalid
	}
	want := 4
	if domain == "local_services" {
		want = 3
	}
	for _, revision := range []Revision{latest.Snapshot.Running, latest.Snapshot.Startup, latest.Snapshot.LastGood} {
		canonical, e := Canonical(revision.Config)
		if e != nil || canonical.Hash != revision.Hash || revision.Config.SchemaVersion != want {
			return image, errV2Invalid
		}
	}
	image.Tip = previous
	image.Projection = latest.Snapshot.Generation
	image.Snapshot = latest.Snapshot
	image.Receipts = latest.Receipts
	_, image.ReceiptIndex, _ = v2Canonical(image.Receipts)
	return image, nil
}

// prepareMigrationV2 imports two independently locked quiescent sources. The
// result is selected *storage preparation*, not an operational global Running.
// Runtime cutover and the legacy downgrade guard belong to coordinator slice D.
func prepareMigrationV2(destination, firewall, local *os.Root, subjects []v2Subject, bindings []v2LegacyBinding, budget v2Budget, now time.Time) (*v2Store, error) {
	return prepareMigrationV2WithHook(destination, firewall, local, subjects, bindings, budget, now, nil)
}

func prepareMigrationV2WithHook(destination, firewall, local *os.Root, subjects []v2Subject, bindings []v2LegacyBinding, budget v2Budget, now time.Time, hook func(string) error) (*v2Store, error) {
	if destination == nil || firewall == nil || local == nil {
		return nil, errV2Invalid
	}
	// Existing checkpoint separation uses descriptor/inode ancestry, not merely
	// path strings. No source lock or destination file is created before this.
	for _, source := range []*os.Root{firewall, local} {
		service := &Service{store: &fileStore{dir: source.Name()}}
		if service.checkCheckpointArea(destination) != nil {
			return nil, errV2Invalid
		}
	}
	fi, _ := firewall.Stat(".")
	li, _ := local.Stat(".")
	if fi == nil || li == nil || os.SameFile(fi, li) {
		return nil, errV2Invalid
	}
	// Fixed domain order: firewall, then local services, then destination.
	fwLock, err := lockLegacyV2(firewall)
	if err != nil {
		return nil, err
	}
	defer fwLock.Close()
	lsLock, err := lockLegacyV2(local)
	if err != nil {
		return nil, err
	}
	defer lsLock.Close()
	fw, err := inspectLegacyV2(firewall, "firewall", nil)
	if err != nil {
		return nil, err
	}
	ls, err := inspectLegacyV2(local, "local_services", nil)
	if err != nil {
		return nil, err
	}
	if fw.Source == ls.Source {
		return nil, errV2Invalid
	}
	lineage, err := v2ID("lineage", 1)
	if err != nil {
		return nil, err
	}
	state := v2State{Format: v2Format, Lineage: lineage, Generation: 1, LiveSlots: v2MaximumOperations, SubjectSlots: v2MaximumSubjects, NamespaceSlots: v2MaximumNamespaces, SubjectSequence: uint64(len(subjects)), Subjects: clone(subjects), Namespaces: []v2Namespace{}, Clock: now.UTC()}
	if !v2ValidState(state) || !v2BindingsValid(fw, ls, subjects, bindings) {
		return nil, errV2Invalid
	}
	store, err := prepareV2(destination, budget, state)
	if err != nil {
		return nil, err
	}
	store.hook = hook
	fail := func(e error) (*v2Store, error) { _ = store.close(); return nil, e }
	fwCopy, err := inspectLegacyV2(firewall, "firewall", store)
	if err != nil {
		return fail(err)
	}
	lsCopy, err := inspectLegacyV2(local, "local_services", store)
	if err != nil {
		return fail(err)
	}
	if fwCopy.Tip != fw.Tip || lsCopy.Tip != ls.Tip || fwCopy.Source != fw.Source || lsCopy.Source != ls.Source || fwCopy.ReceiptIndex != fw.ReceiptIndex || lsCopy.ReceiptIndex != ls.ReceiptIndex {
		return fail(errV2Unavailable)
	}
	composite := func(f, l Revision) v2Composite {
		return v2Composite{Schema: 5, Firewall: v2ComponentReference{4, f.Hash}, LocalServices: v2ComponentReference{3, l.Hash}}
	}
	migration := v2Migration{Format: v2Format, Status: "prepared_requires_global_readback", Firewall: fwCopy, LocalServices: lsCopy, Bindings: clone(bindings), Running: composite(fw.Snapshot.Running, ls.Snapshot.Running), Startup: composite(fw.Snapshot.Startup, ls.Snapshot.Startup)}
	hash, err := store.object(migration)
	if err != nil {
		return fail(err)
	}
	state.Migration = hash
	if err = store.publish(state); err != nil {
		return fail(err)
	}
	return store, nil
}

func v2BindingsValid(fw, ls v2LegacyImage, subjects []v2Subject, bindings []v2LegacyBinding) bool {
	valid := map[string]bool{}
	for _, sub := range subjects {
		valid[sub.ID] = true
	}
	seen := map[string]bool{}
	for _, binding := range bindings {
		image := fw
		if binding.Source == ls.Source {
			image = ls
		} else if binding.Source != fw.Source {
			return false
		}
		key := binding.Source + ":" + binding.Actor
		if binding.Actor == "" || !valid[binding.Subject] || binding.ReceiptIndex != image.ReceiptIndex || seen[key] {
			return false
		}
		seen[key] = true
	}
	for _, image := range []v2LegacyImage{fw, ls} {
		for key := range image.Receipts {
			at := strings.IndexByte(key, ':')
			if at <= 0 || !seen[image.Source+":"+key[:at]] {
				return false
			}
		}
	}
	return true
}

func (s *v2Store) legacyReplay(subject, domain, actor, key, fingerprint string) (Snapshot, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.blocked || !s.subject(subject) || s.state.Migration == "" {
		return Snapshot{}, 0, errV2NotFound
	}
	var migration v2Migration
	if s.readObject(s.state.Migration, &migration) != nil || migration.Format != v2Format {
		return Snapshot{}, 0, errV2Unavailable
	}
	image := migration.Firewall
	if domain == "local_services" {
		image = migration.LocalServices
	} else if domain != "firewall" {
		return Snapshot{}, 0, errV2Invalid
	}
	authorized := false
	for _, binding := range migration.Bindings {
		if binding.Subject == subject && binding.Source == image.Source && binding.Actor == actor && binding.ReceiptIndex == image.ReceiptIndex {
			authorized = true
		}
	}
	if !authorized {
		return Snapshot{}, 0, errV2NotFound
	}
	receipt, ok := image.Receipts[actor+":"+key]
	if !ok {
		return Snapshot{}, 0, errV2NotFound
	}
	if receipt.Fingerprint != fingerprint {
		return Snapshot{}, 0, ErrReplay
	}
	return clone(image.Snapshot), receipt.Generation, nil
}

func (s *v2Store) validateMigration() error {
	var migration v2Migration
	if s.readObject(s.state.Migration, &migration) != nil || migration.Format != v2Format || migration.Status != "prepared_requires_global_readback" || migration.Running.Schema != 5 || migration.Startup.Schema != 5 || migration.Running.Network != nil || migration.Startup.Network != nil || migration.Firewall.Source == migration.LocalServices.Source || !v2BindingsValid(migration.Firewall, migration.LocalServices, s.state.Subjects, migration.Bindings) {
		return errV2Unavailable
	}
	for _, image := range []v2LegacyImage{migration.Firewall, migration.LocalServices} {
		if image.Sequence == 0 || image.Sequence > 2048 || uint64(len(image.Records)) != image.Sequence || image.Projection != image.Snapshot.Generation || !v2HashPattern.MatchString(image.Source) {
			return errV2Unavailable
		}
		previous := ""
		var latest durableState
		for i, hash := range image.Records {
			var record struct {
				Format string `json:"format"`
				Bytes  []byte `json:"bytes"`
			}
			if s.readObject(hash, &record) != nil || record.Format != v2Format {
				return errV2Unavailable
			}
			decoded, err := decodeRecord(record.Bytes, uint64(i+1), previous, "")
			if err != nil {
				return errV2Unavailable
			}
			previous = decoded.Hash
			latest = decoded.State
		}
		_, receiptHash, err := v2Canonical(image.Receipts)
		if err != nil || receiptHash != image.ReceiptIndex || image.Tip != previous || !checkpointEqual(latest, durableState{Snapshot: image.Snapshot, Receipts: image.Receipts}) || latest.Intent != nil || image.Snapshot.Candidate != nil || image.Snapshot.Pending != nil || image.Snapshot.RecoveryRequired {
			return errV2Unavailable
		}
		want := 4
		runningRef, startupRef := migration.Running.Firewall, migration.Startup.Firewall
		if image.Domain == "local_services" {
			want = 3
			runningRef, startupRef = migration.Running.LocalServices, migration.Startup.LocalServices
		} else if image.Domain != "firewall" {
			return errV2Unavailable
		}
		if runningRef.Schema != want || startupRef.Schema != want || runningRef.Revision != image.Snapshot.Running.Hash || startupRef.Revision != image.Snapshot.Startup.Hash || image.Snapshot.Running.Config.SchemaVersion != want || image.Snapshot.Startup.Config.SchemaVersion != want {
			return errV2Unavailable
		}
	}
	return nil
}
