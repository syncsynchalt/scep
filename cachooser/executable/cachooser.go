// Package executablecachooser defines the ExecutableCAChooser cachooser.CAChooser.
package executablecachooser

import (
	"bufio"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
	"os/exec"

	"github.com/go-kit/kit/log"
)

const (
	userExecute os.FileMode = 1 << (6 - 3*iota)
	groupExecute
	otherExecute
)

// New creates a executablecachooser.ExecutableCAChooser.
func New(path string, logger log.Logger) (*ExecutableCAChooser, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	fileMode := fileInfo.Mode()
	if fileMode.IsDir() {
		return nil, errors.New("CA Chooser executable is a directory")
	}

	filePerm := fileMode.Perm()
	if filePerm&(userExecute|groupExecute|otherExecute) == 0 {
		return nil, errors.New("CA Chooser executable is not executable")
	}

	return &ExecutableCAChooser{executable: path, logger: logger}, nil
}

// ExecutableCAChooser implements a cachooser.CAChooser.
// It executes a command, and passes it the raw decrypted CSR.
// The command returns the CA key, CA cert, and optional CA chain to be
// used in signing the CSR.  The optional CA chain is also returned in
// the response.
type ExecutableCAChooser struct {
	executable string
	logger     log.Logger
}

func (v *ExecutableCAChooser) Choose(data []byte, caKeyPass []byte) (*rsa.PrivateKey, []*x509.Certificate, error) {
	cmd := exec.Command(v.executable)
	cmd.Env = append(os.Environ(), "CAKEYPASS="+string(caKeyPass))

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, err
	}
	go func() {
		defer stdin.Close()
		stdin.Write(data)
	}()

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, nil, err
	}
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			v.logger.Log("info", "successer stderr: "+scanner.Text())
		}
	}()

	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}

	outputBytes, err := ioutil.ReadAll(stdout)
	if err != nil {
		return nil, nil, err
	}
	key, rest := pem.Decode(outputBytes)
	if key == nil || key.Type != "RSA PRIVATE KEY" {
		return nil, nil, errors.New("Unrecognized PEM format (no RSA PRIVATE KEY found)")
	}
	decrypted, err := x509.DecryptPEMBlock(key, caKeyPass)
	if err != nil {
		return nil, nil, err
	}
	rsaKey, err := x509.ParsePKCS1PrivateKey(decrypted)
	if err != nil {
		return nil, nil, err
	}

	certs := []*x509.Certificate{}
	for cert, rest := pem.Decode(rest); cert != nil; cert, rest = pem.Decode(rest) {
		if cert.Type != "TRUSTED CERTIFICATE" {
			return nil, nil, errors.New("Unrecognized PEM format (no CERTIFICATE found)")
		}
		certlist, err := x509.ParseCertificates(cert.Bytes)
		if err != nil {
			return nil, nil, err
		}
		certs = append(certs, certlist...)
	}

	if err := cmd.Wait(); err != nil {
		return nil, nil, err
	}

	return rsaKey, certs, err
}
