// Package executablesubjectfilter defines the ExecutableSubjectFilter subjectfilter.SubjectFilter.
package executablesubjectfilter

import (
	"bufio"
	"crypto/x509"
	"crypto/x509/pkix"
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

// New creates a executablesubjectfilter.ExecutableSubjectFilter.
func New(path string, logger log.Logger) (*ExecutableSubjectFilter, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	fileMode := fileInfo.Mode()
	if fileMode.IsDir() {
		return nil, errors.New("Subject Filter executable is a directory")
	}

	filePerm := fileMode.Perm()
	if filePerm&(userExecute|groupExecute|otherExecute) == 0 {
		return nil, errors.New("Subject Filter executable is not executable")
	}

	return &ExecutableSubjectFilter{executable: path, logger: logger}, nil
}

// ExecutableSubjectFilter implements a subjectfilter.SubjectFilter.
// It executes a command, and passes it the raw decrypted CSR.
// The command returns the CA key, CA cert, and optional CA chain to be
// used in signing the CSR.  The optional CA chain is also returned in
// the response.
type ExecutableSubjectFilter struct {
	executable string
	logger     log.Logger
}

func (v *ExecutableSubjectFilter) Filter(data []byte) (*pkix.Name, error) {
	cmd := exec.Command(v.executable)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	go func() {
		defer stdin.Close()
		stdin.Write(data)
	}()

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			v.logger.Log("info", "subjectfilter stderr: "+scanner.Text())
		}
	}()

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	outputBytes, err := ioutil.ReadAll(stdout)
	if err != nil {
		return nil, err
	}

	csr, err := x509.ParseCertificateRequest(outputBytes)
	if err != nil {
		return nil, err
	}

	return &csr.Subject, nil
}
