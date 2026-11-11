package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// Only reviewed public package tuples enter this compiled profile. No runtime override.
const profileText = `ANDEIVA_BOOT_PROFILE_V1
baseline	grub-common	2.12-9+deb13u2	amd64	-
baseline	grub-pc	2.12-9+deb13u2	amd64	-
baseline	grub-pc-bin	2.12-9+deb13u2	amd64	-
baseline	grub2-common	2.12-9+deb13u2	amd64	-
baseline	initramfs-tools	0.148.4	all	-
baseline	initramfs-tools-core	0.148.4	all	-
dependency	fontconfig	2.15.0-2.3	amd64	09794b188e042c90b4a89fcb5afeb276bc231b74ddf8a3efbbc7dfb6f0eac4cb
dependency	fontconfig-config	2.15.0-2.3	amd64	0475c00d02660c07a15085051818625331bb502e053242106aaaa1f2ddb41225
dependency	fonts-cantarell	0.303.1-4	all	21f8160696cd2b51ac104e735fd63d0e2245cd84cf75f17919f1425dce4ea258
dependency	fonts-dejavu-core	2.37-8	all	86635b3d25b3655fc11cb3ecc3af59f0bf19643b02b94f2de48bd10253cdba12
dependency	fonts-dejavu-mono	2.37-8	all	3003e98a5debfdeadc7040a7f715fe9fe6fb67f68deacf6049b54e30f07fc014
dependency	libcairo2	1.18.4-1+b1	amd64	01390b049661e4cc8bd39cef78b41c2587d4035619d3b00d6c7846f43d80bbba
dependency	libdatrie1	0.2.13-3+b1	amd64	339eb88f23d72b8f0b7b1aebcefbab6de600d97b88bc6222dd8aad11d2ca9051
dependency	libevdev2	1.13.4+dfsg-1	amd64	02e85fb9461b85b23f775d5fcf5a31c55d37bec40b63fd98ca5d3a2763714ae7
dependency	libfontconfig1	2.15.0-2.3	amd64	7ae91ec59857cc8e375eb2bdd371a4a69daea38f7787d06d474a847867d852b1
dependency	libfribidi0	1.0.16-1	amd64	f8c35ec8606d0843bd3cf020c6cfa39ddfe717ec58ed826b5855ba9927eb0d55
dependency	libgraphite2-3	1.3.14-2+deb13u1	amd64	1769ba3ed3c1fc75b7fbe02678e32aa24391205813eceef4e1e3500015d12ee3
dependency	libharfbuzz0b	10.2.0-1+deb13u1	amd64	932165b933e5eb633293afe984a983ebe89cb27c923ce7208626f1da6c0c7941
dependency	libpango-1.0-0	1.56.3-1	amd64	4fa38472696d2ddb10bfc9a4692a9446e8478fdb1f48c769a609fc9fec3adfc5
dependency	libpangocairo-1.0-0	1.56.3-1	amd64	6994729c5b7a9649661ec078cf039991f22eff44600543aa917894f83c89cd05
dependency	libpangoft2-1.0-0	1.56.3-1	amd64	b506cf66f78ddf542ddb4bb4a68b3d748d41caa6e190e4480430a6630c1e5105
dependency	libpixman-1-0	0.44.0-3	amd64	3862c87596f6b4b60fc916395fd69aa10af28a875a8e5c081a8cf30ddd120bd6
dependency	libplymouth5	24.004.60-5	amd64	c81e863c17f05837ff85f975dd310d6fc88da663fa8e6a26d2d70b00ed47b1fa
dependency	libthai-data	0.1.29-2	all	fd38d40602834d510a29140bd27fd48485105e834f03dccab1c02e2edaa794dd
dependency	libthai0	0.1.29-2+b1	amd64	e6364c07aeeffe9a95f267061d9df168e48e9dc9126c3b40e19dc829f67702a7
dependency	libxcb-render0	1.17.0-2+b1	amd64	7f6e36978e0f70a590fbad4042a692c70b50ca7cbcdc53fa7e9d9ab87933acc6
dependency	libxcb-shm0	1.17.0-2+b1	amd64	d1777a813f484e89f3dcaadd1d5f2b1a13e9313b6bf70eded16d8ce743208fef
dependency	libxkbcommon0	1.7.0-2	amd64	f75ee544f55acc6a271debfab3ea4ae0458afc89d81cfe1a71137e07d4895b86
dependency	libxrender1	1:0.9.12-1	amd64	9d042dfd5e613be1e02e6ddd0c5c4adef19c5eb08f6db838c2eba672c496dca4
dependency	plymouth	24.004.60-5	amd64	8b452ef36409edf221dcdcc6397f830c5ab73532b3d0f4385321f80674153fd7
dependency	plymouth-label	24.004.60-5	amd64	9698da6e8893293b863afc21ef2bd9526cef0ed6ee5bcf25b008315327b1d349
dependency	plymouth-themes	24.004.60-5	amd64	d9aeb1c0334d5700f9c7fce4e7eb7fb626a2f62d8883d69ab6a4c83f718c8471
`

type profileTuple struct{ version, arch, hash string }

var baselineProfile, dependencyProfile = compiledProfile()

func compiledProfile() (map[string]profileTuple, map[string]profileTuple) {
	baseline, dependencies := map[string]profileTuple{}, map[string]profileTuple{}
	for index, line := range strings.Split(strings.TrimSuffix(profileText, "\n"), "\n") {
		if index == 0 {
			if line != "ANDEIVA_BOOT_PROFILE_V1" {
				panic("ANDEIVA_OFFLINE_PROFILE_BUILD")
			}
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 5 || !packageRE.MatchString(f[1]) || !debVerRE.MatchString(f[2]) || (f[3] != "all" && f[3] != "amd64") {
			panic("ANDEIVA_OFFLINE_PROFILE_BUILD")
		}
		if _, exists := baseline[f[1]]; exists {
			panic("ANDEIVA_OFFLINE_PROFILE_BUILD")
		}
		if _, exists := dependencies[f[1]]; exists {
			panic("ANDEIVA_OFFLINE_PROFILE_BUILD")
		}
		entry := profileTuple{f[2], f[3], f[4]}
		switch f[0] {
		case "baseline":
			if f[4] != "-" {
				panic("ANDEIVA_OFFLINE_PROFILE_BUILD")
			}
			baseline[f[1]] = entry
		case "dependency":
			decoded, err := hex.DecodeString(f[4])
			if err != nil || len(decoded) != 32 || strings.ToLower(f[4]) != f[4] {
				panic("ANDEIVA_OFFLINE_PROFILE_BUILD")
			}
			dependencies[f[1]] = entry
		default:
			panic("ANDEIVA_OFFLINE_PROFILE_BUILD")
		}
	}
	if len(baseline) != 6 || len(dependencies) != 26 {
		panic("ANDEIVA_OFFLINE_PROFILE_BUILD")
	}
	return baseline, dependencies
}

func qualifiedDependency(i item) bool {
	want, ok := dependencyProfile[i.Name]
	return ok && want.version == i.Version && want.arch == i.Arch && want.hash == i.Hash
}

func baseline(root *os.Root) error {
	data, err := read(root, "status", 8<<20)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, paragraph := range strings.Split(strings.TrimSpace(string(data)), "\n\n") {
		fields := map[string]string{}
		for _, line := range strings.Split(paragraph, "\n") {
			pair := strings.SplitN(line, ": ", 2)
			if len(pair) != 2 {
				continue
			}
			switch pair[0] {
			case "Package", "Version", "Architecture", "Status":
				if _, duplicate := fields[pair[0]]; duplicate {
					return reject()
				}
				fields[pair[0]] = pair[1]
			}
		}
		name := fields["Package"]
		if want, required := baselineProfile[name]; required {
			if seen[name] || fields["Status"] != "install ok installed" || fields["Version"] != want.version || fields["Architecture"] != want.arch {
				return reject()
			}
			seen[name] = true
		}
	}
	if len(seen) != len(baselineProfile) {
		return reject()
	}
	return nil
}

// APT 3.0.x pkgAcqArchive uses QuoteString(name/version, "_:") for cache leaves.
func cacheName(i item) string {
	quote := strings.NewReplacer("%", "%25", "_", "%5f", ":", "%3a")
	return quote.Replace(i.Name) + "_" + quote.Replace(i.Version) + "_" + i.Arch + ".deb"
}

func cachePlan(m manifest) string {
	var result strings.Builder
	for _, i := range m.Items {
		fmt.Fprintf(&result, "%s\t%s\t%s\n", i.File, cacheName(i), i.Hash)
	}
	return result.String()
}
