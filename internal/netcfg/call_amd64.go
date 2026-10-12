//go:build windows && amd64

package netcfg

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// On x64, a 16-byte struct argument (the GUID) is passed by reference.
func callSetInterfaceDnsSettings(guid windows.GUID, s *dnsInterfaceSettings) uintptr {
	r, _, _ := procSetInterfaceDnsSettings.Call(uintptr(unsafe.Pointer(&guid)), uintptr(unsafe.Pointer(s)))
	return r
}
