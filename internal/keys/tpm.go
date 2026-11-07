package keys

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

const rawTPMPath = "/dev/tpm0"

// Open opens the TPM at path: a device, or a software TPM's Unix socket (tests). The
// resource manager /dev/tpmrm0 falls back to the raw device when the kernel has none.
func Open(path string) (transport.TPMCloser, error) {
	if path == "/dev/tpmrm0" {
		if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
			if _, err := os.Stat(rawTPMPath); err == nil {
				path = rawTPMPath
			}
		}
	}
	return transport.OpenTPM(path) // a device or a Unix socket
}

type primary struct {
	handle tpm2.TPMHandle
	name   tpm2.TPM2BName
	public tpm2.TPMTPublic
}

func createPrimary(t transport.TPM) (*primary, func(), error) {
	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
	}.Execute(t)
	if err != nil {
		return nil, nil, fmt.Errorf("creating the storage primary: %w", err)
	}
	flush := func() { tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}.Execute(t) }
	pub, err := rsp.OutPublic.Contents()
	if err != nil {
		flush()
		return nil, nil, err
	}
	return &primary{handle: rsp.ObjectHandle, name: rsp.Name, public: *pub}, flush, nil
}

// pcrSelection is pcrs in the SHA-256 bank.
func pcrSelection(pcrs []uint8) tpm2.TPMLPCRSelection {
	bitmap := make([]byte, 3)
	for _, i := range pcrs {
		bitmap[i/8] |= 1 << (i % 8)
	}
	return tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{Hash: tpm2.TPMAlgSHA256, PCRSelect: bitmap}}}
}
