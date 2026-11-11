package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"testing"
)

func TestGRUBCopyIsDeterministicAndProportional(t *testing.T) {
	logo, err := grubLogo("../../../frontend/public")
	if err != nil {
		t.Fatal(err)
	}
	if logo.Bounds().Dx() != 320 || logo.Bounds().Dy() != 160 {
		t.Fatal("GRUB copy must be 320x160")
	}
	var encoded bytes.Buffer
	if err := png.Encode(&encoded, logo); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded.Bytes())
	if hex.EncodeToString(digest[:]) != "44fcce594c0744ba51fd5792236bc4c775c63e8e4903f3fcaabbf0a74bf9cd50" {
		t.Fatal("GRUB copy differs from approved deterministic area reduction")
	}
	wrong := t.TempDir()
	if err := os.WriteFile(filepath.Join(wrong, "andeiva-logo.png"), []byte("not approved artwork"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := grubLogo(wrong); err == nil {
		t.Fatal("unapproved source accepted")
	}
}

func TestAssetsHaveDeterministicDimensionsAndClearCenter(t *testing.T) {
	first, second := background(), background()
	var a, b bytes.Buffer
	if err := png.Encode(&a, first); err != nil {
		t.Fatal(err)
	}
	if err := png.Encode(&b, second); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) || first.Bounds().Dx() != 1280 || first.Bounds().Dy() != 800 {
		t.Fatal("background must be deterministic and 1280x800")
	}
	center := first.NRGBAAt(640, 400)
	if center.R < 242 || center.G < 249 || center.B < 254 {
		t.Fatal("logo region must retain a light background")
	}
	if got := bar(90, true).NRGBAAt(0, 0); got != blue {
		t.Fatalf("segment starts with corporate blue: %v", got)
	}
	if got := bar(90, true).NRGBAAt(89, 0); got != cyan {
		t.Fatalf("segment ends with corporate cyan: %v", got)
	}
}

func TestRendererDoesNotOverwriteExistingFilesOrLinks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "background.png")
	if err := os.WriteFile(path, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writePNG(dir, "background.png", bar(90, true)); err == nil {
		t.Fatal("existing file accepted")
	}
	if got, _ := os.ReadFile(path); string(got) != "preserve" {
		t.Fatal("existing file changed")
	}
	if err := os.Symlink(path, filepath.Join(dir, "activity-track.png")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := writePNG(dir, "activity-track.png", bar(90, true)); err == nil {
		t.Fatal("symlink accepted")
	}
	if err := writePNG(dir, "../outside.png", bar(90, true)); err == nil {
		t.Fatal("unexpected asset path accepted")
	}
	if got := blend(blue, cyan, -1); got != blue {
		t.Fatal("invalid lower blend bound")
	}
	if got := blend(blue, cyan, 2); got != (color.NRGBA{0, 207, 232, 255}) {
		t.Fatal("invalid upper blend bound")
	}
}
