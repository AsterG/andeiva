//go:build !linux

package networkinventory

func interfaceKind(string) Kind { return Unknown }
