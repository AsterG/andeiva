package configpoc

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestV2ReserveNewObjectEnvelopePreservesHistoricalReads(t *testing.T) {
	s, _, _, _ := v2Fixture(t, v2MaximumOperations)
	defer s.close()
	large := struct {
		Payload string `json:"payload"`
	}{strings.Repeat("x", reserveMetadataObjectLimitV2)}
	historical, err := s.object(large)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.enableClosingCreditsLocked(); err != nil {
		t.Fatal(err)
	}
	if hash, err := s.object(large); err != nil || hash != historical {
		t.Fatalf("historical exact bytes refused: %v", err)
	}
	var restored struct {
		Payload string `json:"payload"`
	}
	if err := s.readObject(historical, &restored); err != nil || restored.Payload != large.Payload {
		t.Fatal("historical object unreadable", err)
	}
	large.Payload = "y" + large.Payload
	_, hash, err := v2Canonical(large)
	if err != nil {
		t.Fatal(err)
	}
	before := s.used
	if _, err := s.object(large); !errors.Is(err, errV2Limited) {
		t.Fatalf("new oversized object accepted: %v", err)
	}
	name, _ := v2ObjectName(hash)
	if _, err := s.root.Lstat(name); !os.IsNotExist(err) || s.used != before {
		t.Fatal("rejected object created storage")
	}
	boundary := struct {
		Payload string `json:"payload"`
	}{strings.Repeat("x", reserveMetadataObjectLimitV2-len(`{"payload":""}`))}
	raw, _, err := v2Canonical(boundary)
	if err != nil || len(raw) != reserveMetadataObjectLimitV2 {
		t.Fatal("incorrect boundary fixture", len(raw), err)
	}
	if _, err := s.object(boundary); err != nil {
		t.Fatalf("exact object boundary refused: %v", err)
	}
}
