package main

import (
	"bytes"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"testing"
)

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
