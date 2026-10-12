//go:build windows && arm64

package netcfg

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// On ARM64, a 16-byte struct argument (the GUID) is passed in two registers.
func callSetInterfaceDnsSettings(guid windows.GUID, s *dnsInterfaceSettings) uintptr {
	w := (*[2]uintptr)(unsafe.Pointer(&guid))
	r, _, _ := procSetInterfaceDnsSettings.Call(w[0], w[1], uintptr(unsafe.Pointer(s)))
	return r
}
