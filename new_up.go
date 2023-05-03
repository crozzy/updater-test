package main

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

type newUp struct{}

var _ driver.Updater = (*newUp)(nil)

func (*newUp) Name() string {
	return "newUp"
}

func (*newUp) Parse(ctx context.Context, r io.ReadCloser) ([]*claircore.Vulnerability, error) {
	defer r.Close()
	vs := []*claircore.Vulnerability{}

	buf := make([]byte, 1000)
	_, err := r.Read(buf)
	if err != nil {
		return vs, err
	}
	for _, ln := range strings.Split(string(buf), "\n") {
		info := strings.Split(ln, " ")
		vs = append(vs, &claircore.Vulnerability{
			Name: fmt.Sprintf("problem with %s", info[0]),
			Package: &claircore.Package{
				Name:    info[0],
				Version: info[1],
			},
		})
	}
	return vs, nil
}

func (*newUp) Fetch(context.Context, driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error) {
	vulnFeed := `package1 v1.0.1
package2 v1.1.1
package3 v4.7`
	b := io.NopCloser(strings.NewReader(vulnFeed))
	return b, "something", nil
}
