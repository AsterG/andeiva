// Command render creates decoration and a proportional GRUB copy of the approved logo.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"math"
	"os"
)

var (
	ice  = color.NRGBA{242, 249, 254, 255}
	blue = color.NRGBA{8, 124, 245, 255}
	cyan = color.NRGBA{0, 207, 232, 255}
)

const approvedLogo = "1f79f5ec7f33327c9285c702b63fc5c5a618a28395b2161d594001fdb0199f81"

func grubLogo(sourceDir string) (*image.NRGBA, error) {
	root, err := os.OpenRoot(sourceDir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	info, err := root.Lstat("andeiva-logo.png")
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil, fmt.Errorf("ANDEIVA_BOOT_LOGO_SOURCE")
	}
	f, err := root.Open("andeiva-logo.png")
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return nil, fmt.Errorf("ANDEIVA_BOOT_LOGO_SOURCE")
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != approvedLogo {
		return nil, fmt.Errorf("ANDEIVA_BOOT_LOGO_INTEGRITY")
	}
	source, err := png.Decode(bytes.NewReader(data))
	if err != nil || source.Bounds() != image.Rect(0, 0, 1100, 550) {
		return nil, fmt.Errorf("ANDEIVA_BOOT_LOGO_DIMENSIONS")
	}
	return reduceLogo(source), nil
}

// Area sampling changes resolution only. Both axes use the identical 1100/320 ratio.
func reduceLogo(source image.Image) *image.NRGBA {
	const width, height = 320, 160
	result := image.NewNRGBA(image.Rect(0, 0, width, height))
	const area int64 = 1100 * 550
	channel := func(sum int64) uint8 {
		value := (sum + area*128) / (area * 257)
		if value < 0 {
			return 0
		}
		if value > 255 {
			return 255
		}
		return uint8(value)
	}
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			left, right := x*1100, (x+1)*1100
			top, bottom := y*550, (y+1)*550
			var red, green, blue, alpha int64
			for sy := top / height; sy < (bottom+height-1)/height; sy++ {
				for sx := left / width; sx < (right+width-1)/width; sx++ {
					weight := int64(min(right, (sx+1)*width)-max(left, sx*width)) * int64(min(bottom, (sy+1)*height)-max(top, sy*height))
					r, g, b, a := source.At(sx, sy).RGBA()
					red += int64(r) * weight
					green += int64(g) * weight
					blue += int64(b) * weight
					alpha += int64(a) * weight
				}
			}
			result.SetNRGBA(x, y, color.NRGBA{channel(red), channel(green), channel(blue), channel(alpha)})
		}
	}
	return result
}

func blend(a, b color.NRGBA, t float64) color.NRGBA {
	t = math.Max(0, math.Min(1, t))
	return color.NRGBA{uint8(float64(a.R)*(1-t) + float64(b.R)*t), uint8(float64(a.G)*(1-t) + float64(b.G)*t), uint8(float64(a.B)*(1-t) + float64(b.B)*t), 255}
}

func background() *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, 1280, 800))
	for y := 0; y < 800; y++ {
		for x := 0; x < 1280; x++ {
			p := blend(color.NRGBA{255, 255, 255, 255}, ice, float64(y)/800)
			// Restrained diagonal bands leave the center clear for the intact logo.
			d := float64(x) + float64(y)*0.74
			if d < 168 {
				p = blend(cyan, blue, d/168)
			} else if d < 214 {
				p = blend(cyan, p, 0.72)
			}
			if d > 1570 {
				p = blend(blue, cyan, (d-1570)/300)
			} else if d > 1520 {
				p = blend(cyan, p, 0.72)
			}
			wave := 733 + 25*math.Sin(float64(x)/230)
			if math.Abs(float64(y)-wave) < 1.4 {
				p = blend(cyan, p, 0.72)
			}
			img.SetNRGBA(x, y, p)
		}
	}
	return img
}

func bar(width int, segment bool) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, width, 8))
	for y := 0; y < 8; y++ {
		for x := 0; x < width; x++ {
			p := color.NRGBA{216, 230, 243, 255}
			if segment {
				p = blend(blue, cyan, float64(x)/float64(width-1))
			}
			img.SetNRGBA(x, y, p)
		}
	}
	return img
}

func writePNG(dir, name string, img image.Image) error {
	switch name {
	case "background.png", "activity-track.png", "activity-segment.png", "andeiva-grub-logo.png":
	default:
		return fmt.Errorf("unsupported decorative asset: %q", name)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := png.Encode(f, img); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "Usage: render OUTPUT_DIRECTORY APPROVED_LOGO_DIRECTORY")
		os.Exit(2)
	}
	logo, err := grubLogo(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, asset := range []struct {
		name string
		img  image.Image
	}{{"background.png", background()}, {"activity-track.png", bar(360, false)}, {"activity-segment.png", bar(90, true)}, {"andeiva-grub-logo.png", logo}} {
		if err := writePNG(os.Args[1], asset.name, asset.img); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}
