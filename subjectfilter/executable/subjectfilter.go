// Package executablesubjectfilter defines the ExecutableSubjectFilter subjectfilter.SubjectFilter.
package executablesubjectfilter

import (
	"bufio"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"

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

	if err := cmd.Wait(); err != nil {
		v.logger.Log("err", err)
		return nil, err
	}

	appendRDNs := func(in pkix.RDNSequence, values []string, oid asn1.ObjectIdentifier) pkix.RDNSequence {
		s := make([]pkix.AttributeTypeAndValue, len(values))
		for i, value := range values {
			s[i].Type = oid
			s[i].Value = value
		}
		return append(in, s)
	}

	reader := bufio.NewReader(stdout)
	var subjSeq pkix.RDNSequence
	for {
		s, err := reader.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		s = s[:len(s)-1]

		// line in the form of 1.2.3.4=urlescaped+value+for+oid
		eq := strings.Index(s, "=")
		if eq == -1 {
			return nil, errors.New("Could not find delimiter in " + s)
		}

		oid, err := oidFromString(s[:eq])
		if err != nil {
			return nil, err
		}

		val, err := url.QueryUnescape(s[eq+1:])
		if err != nil {
			return nil, err
		}

		subjSeq = appendRDNs(subjSeq, []string{val}, oid)
	}
	var newSubject pkix.Name
	newSubject.FillFromRDNSequence(&subjSeq)

	return &newSubject, nil
}

func oidFromString(s string) ([]int, error) {
	sa := strings.Split(s, ".")
	oid := make([]int, len(sa))
	for i, v := range sa {
		ss, err := strconv.Atoi(v)
		if err != nil {
			return nil, err
		}
		oid[i] = ss
	}
	return oid, nil
}
