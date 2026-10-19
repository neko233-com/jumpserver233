package assetdiscovery

import (
	"cmp"
	"net/netip"
	"slices"
	"strings"
)

const MaxAddresses = 1024
const MaxEndpoints = 8192

func usable(ip netip.Addr) bool {
	return ip.IsValid() && ip.Zone() == "" && (ip.IsGlobalUnicast() || ip.IsLoopback()) && !ip.IsMulticast()
}

// Addresses accepts literal IPs, CIDRs and inclusive start-end ranges. DNS is
// deliberately absent: a saved scan range cannot change through DNS rebinding.
func Addresses(includes, excludes []string) ([]string, error) {
	if len(includes) == 0 || len(includes) > 128 || len(excludes) > 128 {
		return nil, ErrInvalid
	}
	selected := map[netip.Addr]bool{}
	expand := func(values []string, remove bool) error {
		for _, text := range values {
			text = strings.TrimSpace(text)
			if text == "" || len(text) > 256 {
				return ErrInvalid
			}
			var first, last netip.Addr
			var prefix netip.Prefix
			if strings.Contains(text, "/") {
				p, e := netip.ParsePrefix(text)
				if e != nil || p.Addr().Zone() != "" || p.Addr().Is4In6() {
					return ErrInvalid
				}
				prefix = p.Masked()
				first = prefix.Addr()
				if !remove && prefix.Addr().BitLen()-prefix.Bits() > 10 {
					return ErrCapacity
				}
				if remove {
					for ip := range selected {
						if prefix.Contains(ip) {
							delete(selected, ip)
						}
					}
					continue
				}
			} else if strings.Contains(text, "-") {
				parts := strings.Split(text, "-")
				if len(parts) != 2 {
					return ErrInvalid
				}
				var e error
				first, e = netip.ParseAddr(strings.TrimSpace(parts[0]))
				if e != nil {
					return ErrInvalid
				}
				last, e = netip.ParseAddr(strings.TrimSpace(parts[1]))
				if e != nil {
					return ErrInvalid
				}
				first, last = first.Unmap(), last.Unmap()
				if first.BitLen() != last.BitLen() || first.Compare(last) > 0 {
					return ErrInvalid
				}
			} else {
				var e error
				first, e = netip.ParseAddr(text)
				if e != nil {
					return ErrInvalid
				}
				first = first.Unmap()
				last = first
			}
			if !usable(first) || last.IsValid() && !usable(last) {
				return ErrInvalid
			}
			if remove && last.IsValid() {
				for ip := range selected {
					if ip.BitLen() == first.BitLen() && ip.Compare(first) >= 0 && ip.Compare(last) <= 0 {
						delete(selected, ip)
					}
				}
				continue
			}
			count := 0
			for ip := first; ip.IsValid(); ip = ip.Next() {
				if prefix.IsValid() && !prefix.Contains(ip) || last.IsValid() && ip.Compare(last) > 0 {
					break
				}
				count++
				if count > MaxAddresses {
					return ErrCapacity
				}
				if usable(ip) {
					// For IPv4 networks larger than a point-to-point link, skip
					// network/broadcast addresses; /31 and /32 retain every IP.
					skip := prefix.IsValid() && ip.Is4() && prefix.Bits() < 31 && (ip == first || !prefix.Contains(ip.Next()))
					if !skip {
						if remove {
							delete(selected, ip)
						} else {
							selected[ip] = true
						}
					}
				}
				if len(selected) > MaxAddresses {
					return ErrCapacity
				}
			}
		}
		return nil
	}
	if e := expand(includes, false); e != nil {
		return nil, e
	}
	if e := expand(excludes, true); e != nil {
		return nil, e
	}
	if len(selected) == 0 {
		return nil, ErrInvalid
	}
	ips := make([]netip.Addr, 0, len(selected))
	for ip := range selected {
		ips = append(ips, ip)
	}
	slices.SortFunc(ips, func(a, b netip.Addr) int { return a.Compare(b) })
	out := make([]string, len(ips))
	for i, ip := range ips {
		out[i] = ip.String()
	}
	return out, nil
}

func normalizePorts(ports []int) ([]int, error) {
	if len(ports) < 1 || len(ports) > 16 {
		return nil, ErrInvalid
	}
	ports = slices.Clone(ports)
	slices.SortFunc(ports, cmp.Compare[int])
	ports = slices.Compact(ports)
	for _, port := range ports {
		if port < 1 || port > 65535 {
			return nil, ErrInvalid
		}
	}
	return ports, nil
}
