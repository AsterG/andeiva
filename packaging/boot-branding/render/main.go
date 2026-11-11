// Command render creates original decorative assets; it never opens the logo.
package main

import (
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
)

var (
	ice  = color.NRGBA{242, 249, 254, 255}
	blue = color.NRGBA{8, 124, 245, 255}
	cyan = color.NRGBA{0, 207, 232, 255}
)

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
	case "background.png", "activity-track.png", "activity-segment.png":
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
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "Usage: render OUTPUT_DIRECTORY")
		os.Exit(2)
	}
	for _, asset := range []struct {
		name string
		img  image.Image
	}{{"background.png", background()}, {"activity-track.png", bar(360, false)}, {"activity-segment.png", bar(90, true)}} {
		if err := writePNG(os.Args[1], asset.name, asset.img); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}
