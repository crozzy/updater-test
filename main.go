package main

import (
	"context"
	"fmt"

	"github.com/crozzy/updater-test/datastore"
	"github.com/quay/claircore/enricher/cvss"
	"github.com/quay/claircore/libvuln"
	"github.com/quay/claircore/libvuln/driver"
)

func main() {
	ctx := context.Background()
	matcherStore, err := datastore.NewSQLiteMatcherStore("./db", true)
	if err != nil {
		fmt.Println(err)
		return
	}

	matcherOpts := &libvuln.Options{
		Updaters:                 []driver.Updater{&newUp{}},
		Store:                    matcherStore,
		Locker:                   NewLocalLockSource(),
		DisableBackgroundUpdates: true,
		UpdateWorkers:            1,
		Enrichers: []driver.Enricher{
			&cvss.Enricher{},
		},
	}
	lv, err := libvuln.New(ctx, matcherOpts)
	if err != nil {
		fmt.Printf("error creating Libvuln: %v\n", err)
		return
	}
	if err := lv.FetchUpdates(ctx); err != nil {
		fmt.Printf("error updating vulnerabilities: %v\n", err)
		return
	}

}
