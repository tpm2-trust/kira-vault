package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// reachable checks what init writes into the configuration against what the shipped
// deployments reach: the unit (DeviceAllow, ProtectSystem=strict) and the container
// (one device, one runtime volume) reach the TPM at /dev/tpmrm0 (or /dev/tpm0 where
// there is no resource manager) and an admin socket under /run/kira-vault/ alone.
// A vault made for anything else would not start under either. Tests replace it.
var reachable = checkReachable

// adminSocketDir is where the unit's RuntimeDirectory and the container's volume put
// the admin socket.
const adminSocketDir = "/run/kira-vault"

func checkReachable(tpm, sock string) error {
	switch tpm {
	case "/dev/tpmrm0", "/dev/tpm0":
	default:
		st, err := os.Stat(tpm)
		if !socketTPM || err != nil || st.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("--tpm %s: the unit and the container reach the TPM at /dev/tpmrm0 (or /dev/tpm0) alone", tpm)
		}
	}
	if filepath.Dir(filepath.Clean(sock)) != adminSocketDir {
		return fmt.Errorf("--admin-socket %s: the unit and the container reach an admin socket in %s/ alone", sock, adminSocketDir)
	}
	return nil
}
