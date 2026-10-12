//go:build windows

// Package netcfg points Windows DNS at the loopback resolver and restores the
// original settings. Routing method (PLAN 2.1): per-adapter DNS via
// SetInterfaceDnsSettings, re-applied on network changes. Originals are
// saved to state.json before the first change and restored by uninstall,
// service stop and the watchdog.
package netcfg

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	LoopbackV4 = "127.0.0.1"
	LoopbackV6 = "::1"
)

// Adapter is a network interface as far as DNS routing cares.
type Adapter struct {
	GUID        string   `json:"guid"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Index       uint32   `json:"index"`
	Up          bool     `json:"up"`
	VPN         bool     `json:"vpn"`
	HasGateway  bool     `json:"has_gateway"`
	DNS         []string `json:"dns"` // effective servers Windows reports
	Suffix      string   `json:"suffix,omitempty"`
}

var vpnWords = []string{
	"vpn", "wireguard", "wintun", "tap-windows", "openvpn", "tailscale", "zerotier",
	"anyconnect", "cisco", "fortinet", "forticlient", "globalprotect", "pangp", "juniper",
	"pulse secure", "nordlynx", "proton", "mullvad", "expressvpn", "surfshark", "warp",
}

// Adapters lists interfaces, skipping loopback.
func Adapters() ([]Adapter, error) {
	size := uint32(16 * 1024)
	var buf []byte
	for i := 0; i < 4; i++ {
		buf = make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC,
			windows.GAA_FLAG_INCLUDE_GATEWAYS|windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST,
			0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			return nil, err
		}
		if i == 3 {
			return nil, err
		}
	}
	var out []Adapter
	for a := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); a != nil; a = a.Next {
		if a.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK {
			continue
		}
		ad := Adapter{
			GUID:        windows.BytePtrToString(a.AdapterName),
			Name:        windows.UTF16PtrToString(a.FriendlyName),
			Description: windows.UTF16PtrToString(a.Description),
			Index:       a.IfIndex,
			Up:          a.OperStatus == windows.IfOperStatusUp,
			HasGateway:  a.FirstGatewayAddress != nil,
			Suffix:      windows.UTF16PtrToString(a.DnsSuffix),
		}
		for d := a.FirstDnsServerAddress; d != nil; d = d.Next {
			if ip := d.Address.IP(); ip != nil {
				ad.DNS = append(ad.DNS, ip.String())
			}
		}
		desc := strings.ToLower(ad.Description + " " + ad.Name)
		ad.VPN = a.IfType == windows.IF_TYPE_PPP || a.IfType == windows.IF_TYPE_TUNNEL || a.IfType == 53 /* PROP_VIRTUAL */
		for _, w := range vpnWords {
			if strings.Contains(desc, w) {
				ad.VPN = true
			}
		}
		out = append(out, ad)
	}
	return out, nil
}

// PointsAtUs reports whether the adapter's DNS is our loopback listener.
func (a Adapter) PointsAtUs() bool {
	for _, d := range a.DNS {
		ip := net.ParseIP(d)
		if ip == nil || !ip.IsLoopback() {
			return false
		}
	}
	return len(a.DNS) > 0
}

// Routable reports whether we should point this adapter at loopback.
// Adapters without a gateway (Hyper-V default switch, WSL) carry no
// internet DNS traffic, so we leave them alone.
func (a Adapter) Routable(forceVPN bool) bool {
	return a.Up && a.HasGateway && (!a.VPN || forceVPN)
}

// Original DNS settings for one adapter. Empty means "from DHCP".
type Original struct {
	Name string `json:"name"`
	V4   string `json:"v4"`
	V6   string `json:"v6"`
}

// State is persisted to state.json.
type State struct {
	Adapters map[string]Original `json:"adapters"`
	Saved    time.Time           `json:"saved"`
}

// Manager applies and restores routing. Safe for concurrent use.
type Manager struct {
	Path     string // state.json
	ForceVPN bool
	Logf     func(string, ...any)
	mu       sync.Mutex
}

func (m *Manager) logf(f string, a ...any) {
	if m.Logf != nil {
		m.Logf(f, a...)
	}
}

func (m *Manager) load() State {
	s := State{Adapters: map[string]Original{}}
	if b, err := os.ReadFile(m.Path); err == nil {
		json.Unmarshal(b, &s)
		if s.Adapters == nil {
			s.Adapters = map[string]Original{}
		}
	}
	return s
}

func (m *Manager) save(s State) error {
	s.Saved = time.Now()
	b, _ := json.MarshalIndent(s, "", "  ")
	os.MkdirAll(filepath.Dir(m.Path), 0o755)
	tmp := m.Path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, m.Path)
}

// HasState reports whether there are saved originals to restore.
func (m *Manager) HasState() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.load().Adapters) > 0
}

// Apply points every routable adapter at loopback, saving originals first.
// It returns the names of adapters it changed.
func (m *Manager) Apply() ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ads, err := Adapters()
	if err != nil {
		return nil, err
	}
	st := m.load()
	var changed []string
	var errs []error
	for _, a := range ads {
		if !a.Routable(m.ForceVPN) {
			continue
		}
		v4, v6 := StaticDNS(a.GUID)
		if v4 == LoopbackV4 && (v6 == LoopbackV6 || v6 == "") {
			if v6 == "" {
				setDNS(a, true, LoopbackV6)
			}
			continue
		}
		if _, saved := st.Adapters[a.GUID]; !saved {
			st.Adapters[a.GUID] = Original{Name: a.Name, V4: v4, V6: v6}
			// Persist before touching anything, so a crash mid-way can still restore.
			if err := m.save(st); err != nil {
				return changed, fmt.Errorf("saving original DNS: %w", err)
			}
		}
		if err := setDNS(a, false, LoopbackV4); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", a.Name, err))
			continue
		}
		setDNS(a, true, LoopbackV6) // IPv6 may be unbound on this adapter; not fatal
		changed = append(changed, a.Name)
	}
	if len(changed) > 0 {
		Flush()
		m.logf("DNS pointed at ab-win on: %s", strings.Join(changed, ", "))
	}
	return changed, errors.Join(errs...)
}

// Restore puts back the saved DNS settings and deletes state.json.
func (m *Manager) Restore() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.load()
	ads, _ := Adapters()
	byGUID := map[string]Adapter{}
	for _, a := range ads {
		byGUID[a.GUID] = a
	}
	var errs []error
	for guid, o := range st.Adapters {
		a, ok := byGUID[guid]
		if !ok {
			a = Adapter{GUID: guid, Name: o.Name}
		}
		if err := setDNS(a, false, o.V4); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", o.Name, err))
			continue
		}
		setDNS(a, true, o.V6)
		delete(st.Adapters, guid)
	}
	// Adapters we never saw but that still point at loopback (state lost):
	// fall back to DHCP, which is the right answer for almost every home PC.
	for _, a := range ads {
		v4, v6 := StaticDNS(a.GUID)
		if v4 == LoopbackV4 {
			setDNS(a, false, "")
		}
		if v6 == LoopbackV6 {
			setDNS(a, true, "")
		}
	}
	Flush()
	if len(st.Adapters) == 0 {
		os.Remove(m.Path)
	} else {
		m.save(st)
	}
	return errors.Join(errs...)
}

// NetworkServers returns the DNS servers the network itself provides
// (original static or DHCP), never loopback. Used for local names and as
// the last-resort upstream.
func (m *Manager) NetworkServers() []string {
	m.mu.Lock()
	st := m.load()
	m.mu.Unlock()
	ads, _ := Adapters()
	var out []string
	add := func(list string) {
		for _, s := range splitServers(list) {
			ip := net.ParseIP(s)
			if ip != nil && !ip.IsLoopback() && !ip.IsUnspecified() && !slices.Contains(out, s) {
				out = append(out, s)
			}
		}
	}
	for _, a := range ads {
		if !a.Up || !a.HasGateway || (a.VPN && !m.ForceVPN) {
			continue
		}
		if o, ok := st.Adapters[a.GUID]; ok && o.V4 != "" {
			add(o.V4)
		} else {
			add(dhcpDNS(a.GUID, false))
		}
	}
	for _, a := range ads {
		if a.Up && a.HasGateway && !a.PointsAtUs() {
			add(strings.Join(a.DNS, " "))
		}
	}
	return out
}

// SearchDomains returns the DHCP/connection DNS suffixes of active adapters.
func SearchDomains() []string {
	ads, _ := Adapters()
	var out []string
	for _, a := range ads {
		s := strings.ToLower(strings.TrimSuffix(a.Suffix, "."))
		if a.Up && s != "" && strings.Contains(s, ".") && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

func splitServers(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == ';' })
}

const (
	tcpip4 = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\`
	tcpip6 = `SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\`
)

func regString(path, name string) string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, _ := k.GetStringValue(name)
	return strings.TrimSpace(v)
}

// StaticDNS returns the statically configured servers ("" = DHCP) for v4 and v6.
func StaticDNS(guid string) (v4, v6 string) {
	return regString(tcpip4+guid, "NameServer"), regString(tcpip6+guid, "NameServer")
}

func dhcpDNS(guid string, v6 bool) string {
	if v6 {
		return regString(tcpip6+guid, "DhcpNameServer")
	}
	return regString(tcpip4+guid, "DhcpNameServer")
}

// DNS_INTERFACE_SETTINGS (netioapi.h), version 1.
type dnsInterfaceSettings struct {
	Version             uint32
	Flags               uint64
	Domain              *uint16
	NameServer          *uint16
	SearchList          *uint16
	RegistrationEnabled uint32
	RegisterAdapterName uint32
	EnableLLMNR         uint32
	QueryAdapterName    uint32
	ProfileNameServer   *uint16
}

const (
	dnsSettingIPv6       = 0x1
	dnsSettingNameserver = 0x2
)

var (
	iphlpapi                    = windows.NewLazySystemDLL("iphlpapi.dll")
	procSetInterfaceDnsSettings = iphlpapi.NewProc("SetInterfaceDnsSettings")
	dnsapi                      = windows.NewLazySystemDLL("dnsapi.dll")
	procDnsFlushResolverCache   = dnsapi.NewProc("DnsFlushResolverCache")
)

// setDNS sets an adapter's static DNS servers; servers == "" means DHCP.
func setDNS(a Adapter, v6 bool, servers string) error {
	guid, err := windows.GUIDFromString(a.GUID)
	if err == nil && procSetInterfaceDnsSettings.Find() == nil {
		s := dnsInterfaceSettings{Version: 1, Flags: dnsSettingNameserver}
		if v6 {
			s.Flags |= dnsSettingIPv6
		}
		// Windows expects comma-separated servers here.
		s.NameServer, _ = windows.UTF16PtrFromString(strings.Join(splitServers(servers), ","))
		r := callSetInterfaceDnsSettings(guid, &s)
		if r == 0 {
			return nil
		}
		err = syscall.Errno(r)
	}
	// Fallback for builds without the API: netsh.
	if a.Name == "" {
		return err
	}
	family := "ipv4"
	if v6 {
		family = "ipv6"
	}
	list := splitServers(servers)
	var cmd *exec.Cmd
	if len(list) == 0 {
		cmd = exec.Command("netsh", "interface", family, "set", "dnsservers", "name="+a.Name, "source=dhcp")
	} else {
		cmd = exec.Command("netsh", "interface", family, "set", "dnsservers", "name="+a.Name, "source=static", "address="+list[0], "register=primary", "validate=no")
	}
	if out, nerr := cmd.CombinedOutput(); nerr != nil {
		return fmt.Errorf("netsh: %v: %s", nerr, strings.TrimSpace(string(out)))
	}
	for i, s := range list[1:] {
		exec.Command("netsh", "interface", family, "add", "dnsservers", "name="+a.Name, "address="+s, fmt.Sprintf("index=%d", i+2), "validate=no").Run()
	}
	return nil
}

// Flush clears the Windows DNS client cache so changes apply immediately.
func Flush() {
	if procDnsFlushResolverCache.Find() == nil {
		procDnsFlushResolverCache.Call()
	}
}

// Watch calls fn (debounced) whenever an IP interface changes, and every
// interval as a safety net. It returns a stop function.
func Watch(interval time.Duration, fn func()) (stop func()) {
	trigger := make(chan struct{}, 1)
	done := make(chan struct{})
	cb := syscall.NewCallback(func(ctx, row, typ uintptr) uintptr {
		select {
		case trigger <- struct{}{}:
		default:
		}
		return 0
	})
	var h windows.Handle
	notifyErr := windows.NotifyIpInterfaceChange(windows.AF_UNSPEC, cb, nil, false, &h)
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				fn()
			case <-trigger:
				// Let the adapter settle (DHCP lease, VPN setup) before re-applying.
				time.Sleep(3 * time.Second)
				select {
				case <-trigger:
				default:
				}
				fn()
			}
		}
	}()
	return func() {
		if notifyErr == nil {
			windows.CancelMibChangeNotify2(h)
		}
		close(done)
	}
}
