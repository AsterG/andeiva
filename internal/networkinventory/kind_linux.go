//go:build linux

package networkinventory

import (
	"os"
	"path/filepath"
	"strings"
)

func interfaceKind(name string) Kind {
	return classifyLinux(name, os.Readlink)
}

// Only fixed sysfs paths derived from a validated OS interface name are read.
// Link targets are checked without following them into an arbitrary filesystem.
func classifyLinux(name string, readlink func(string) (string, error)) Kind {
	if !validName(name) {
		return Unknown
	}
	class := filepath.Join("/sys/class/net", name)
	link, err := readlink(class)
	if err != nil {
		return Unknown
	}
	target, ok := sysfsTarget(class, link)
	if !ok || filepath.Base(target) != name || filepath.Base(filepath.Dir(target)) != "net" {
		return Unknown
	}
	if target == filepath.Join("/sys/devices/virtual/net", name) {
		return Virtual
	}
	device := filepath.Join(target, "device")
	link, err = readlink(device)
	if err != nil {
		return Unknown
	}
	if _, ok := sysfsTarget(device, link); !ok {
		return Unknown
	}
	return DeviceBacked
}

func sysfsTarget(path, link string) (string, bool) {
	if link == "" || len(link) > 4096 || strings.IndexByte(link, 0) >= 0 {
		return "", false
	}
	target := link
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(path), target)
	}
	target = filepath.Clean(target)
	return target, strings.HasPrefix(target, "/sys/devices/")
}
