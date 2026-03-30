package backend

import (
	"time"

	"go.skymeyer.dev/pkg/fflags"
)

var ffs *fflags.Manager

func InitFFManager(file string, refresh time.Duration) error {
	m, err := fflags.NewManager(file, fflags.WithRefresh(refresh))
	if err != nil {
		return err
	}
	ffs = m
	return nil
}
