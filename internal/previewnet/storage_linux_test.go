package previewnet

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestMetadataDecodeRejectsUnknownFieldsAndTrailingDocuments(t *testing.T) {
	data, e := json.Marshal(validMetadata())
	if e != nil {
		t.Fatal(e)
	}
	for _, data := range [][]byte{append(append([]byte{}, data...), data...), []byte(`{"schema_version":1,"command":"nft"}`), []byte(`{"schema_version":`)} {
		var m Metadata
		if decode(data, &m) == nil {
			t.Fatal("invalid document accepted")
		}
	}
}

func TestOwnedFilesRejectSymlinksModesAndOversize(t *testing.T) {
	d := t.TempDir()
	regular := filepath.Join(d, "record")
	if e := os.WriteFile(regular, []byte("data"), 0600); e != nil {
		t.Fatal(e)
	}
	link := filepath.Join(d, "link")
	if e := os.Symlink(regular, link); e != nil {
		t.Fatal(e)
	}
	if _, e := ownedRegular(link, 0600, 10); e == nil {
		t.Fatal("symlink accepted")
	}
	if _, e := ownedRegular(regular, 0644, 10); e == nil {
		t.Fatal("incorrect mode accepted")
	}
	if _, e := ownedRegular(regular, 0600, 1); e == nil {
		t.Fatal("oversize accepted")
	}
	if _, e := ownedRegular(d, 0600, 10); e == nil {
		t.Fatal("directory accepted")
	}
	if os.Geteuid() != 0 {
		if _, e := ownedRegular(regular, 0600, 10); e == nil {
			t.Fatal("non-root owner accepted")
		}
	}
}

func TestInvalidRuntimeOptionsCannotCreateNamespace(t *testing.T) {
	for _, o := range []Options{{}, {UID: 1, GID: 1, Executable: "relative"}, {UID: 0, GID: 1, Executable: "/unused"}, {UID: 1, GID: 0, Executable: "/unused"}} {
		if e := Run(t.Context(), o); e == nil {
			t.Fatal("invalid options accepted")
		}
	}
}
