package bootstate

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Volume is the dm-crypt device a path is on.
type Volume struct {
	Name string // its dm name, as crypttab names it
	UUID string // its LUKS UUID, with dashes
}

// host is where the volume is looked up: the real /sys and /proc, or a test's tree.
type host struct {
	sys       string // /sys
	mountinfo string // /proc/self/mountinfo
	// dev is a path's device (major, minor): of the file itself, or of the block
	// device node it names.
	dev func(path string, node bool) (uint32, uint32, error)
}

var realHost = host{sys: "/sys", mountinfo: "/proc/self/mountinfo", dev: func(path string, node bool) (uint32, uint32, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0, 0, err
	}
	if node {
		if st.Mode&unix.S_IFMT != unix.S_IFBLK {
			return 0, 0, fmt.Errorf("%s is no block device", path)
		}
		return unix.Major(st.Rdev), unix.Minor(st.Rdev), nil
	}
	return unix.Major(st.Dev), unix.Minor(st.Dev), nil
}}

// ErrNotEncrypted is a path on no dm-crypt device.
var ErrNotEncrypted = errors.New("not on an encrypted volume (dm-crypt)")

// VolumeOf is the dm-crypt device path is on, through the block devices it stacks on
// (LVM, a partition) down to the crypt device.
func VolumeOf(path string) (*Volume, error) { return realHost.volumeOf(path) }

func (h host) volumeOf(path string) (*Volume, error) {
	major, minor, err := h.blockDev(path)
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(h.sys, "dev", "block", fmt.Sprintf("%d:%d", major, minor))
	return h.crypt(dir, 0)
}

// blockDev is the block device of path's file system: the file's own device, or -
// where that is no block device, as on btrfs - the device its mount names.
func (h host) blockDev(path string) (uint32, uint32, error) {
	major, minor, err := h.dev(path, false)
	if err != nil {
		return 0, 0, err
	}
	if _, err := os.Stat(filepath.Join(h.sys, "dev", "block", fmt.Sprintf("%d:%d", major, minor))); err == nil {
		return major, minor, nil
	}
	source, err := h.mountSource(path)
	if err != nil {
		return 0, 0, err
	}
	return h.dev(source, true)
}

// mountSource is the source of the mount path is in: the longest mount point it is
// under.
func (h host) mountSource(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	f, err := os.Open(h.mountinfo)
	if err != nil {
		return "", err
	}
	defer f.Close()
	best, source := -1, ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// ID PARENT MAJ:MIN ROOT MOUNTPOINT OPTIONS [OPTIONAL...] - FSTYPE SOURCE SUPER
		left, right, ok := strings.Cut(sc.Text(), " - ")
		fields, rest := strings.Fields(left), strings.Fields(right)
		if !ok || len(fields) < 5 || len(rest) < 2 {
			continue
		}
		mp := unescapeMount(fields[4])
		if (abs == mp || strings.HasPrefix(abs, strings.TrimSuffix(mp, "/")+"/")) && len(mp) > best {
			best, source = len(mp), rest[1]
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	if !strings.HasPrefix(source, "/dev/") {
		return "", fmt.Errorf("%s is on %q, no block device", path, source)
	}
	return source, nil
}

// unescapeMount undoes mountinfo's octal escapes (\040 for a space).
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			var c byte
			if _, err := fmt.Sscanf(s[i+1:i+4], "%03o", &c); err == nil {
				b.WriteByte(c)
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// crypt walks from a block device's /sys directory down its slaves to the dm-crypt
// device; several crypt devices beneath one is no answer.
func (h host) crypt(dir string, depth int) (*Volume, error) {
	if depth > 8 {
		return nil, errors.New("the block devices stack deeper than 8")
	}
	uuid, _ := os.ReadFile(filepath.Join(dir, "dm", "uuid"))
	if u := string(bytes.TrimSpace(uuid)); strings.HasPrefix(u, "CRYPT-") {
		name, err := os.ReadFile(filepath.Join(dir, "dm", "name"))
		if err != nil {
			return nil, err
		}
		luks, err := luksUUID(u)
		if err != nil {
			return nil, err
		}
		return &Volume{Name: string(bytes.TrimSpace(name)), UUID: luks}, nil
	}
	slaves, _ := os.ReadDir(filepath.Join(dir, "slaves"))
	var found *Volume
	for _, s := range slaves {
		v, err := h.crypt(filepath.Join(h.sys, "class", "block", s.Name()), depth+1)
		if errors.Is(err, ErrNotEncrypted) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if found != nil {
			return nil, errors.New("on more than one encrypted volume")
		}
		found = v
	}
	if found == nil {
		// A partition's parent: /sys/class/block/sda1/.. is sda, which is no crypt device.
		return nil, ErrNotEncrypted
	}
	return found, nil
}

// luksUUID is the LUKS UUID in a dm-crypt device's dm UUID,
// "CRYPT-LUKS2-<32 hex digits>-<name>", with its dashes.
func luksUUID(dm string) (string, error) {
	parts := strings.SplitN(dm, "-", 4)
	if len(parts) < 3 || !strings.HasPrefix(parts[1], "LUKS") || len(parts[2]) != 32 {
		return "", fmt.Errorf("the dm-crypt device %q is no LUKS volume", dm)
	}
	h := strings.ToLower(parts[2])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}
