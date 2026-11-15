// CDH: CertBot DANE hook
// Copyright (C) 2019-2026  Yishen Miao
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	// envPrefix is the prefix of the environment variables holding
	// provider settings.
	envPrefix = "CDH_"
	// envFileSuffix is the suffix of the environment variables holding
	// the path to a file with a provider setting.
	envFileSuffix = "_FILE"
)

// setting is a setting of a provider that can be set from the environment.
type setting struct {
	// key is the name of the setting in the JSON configuration file.
	key string
	// env is the name of the environment variable holding the setting.
	env string

	value reflect.Value
}

// settings returns the settings of a provider. p must be a pointer to a
// struct. Its settings are the exported fields with a JSON name that hold a
// string, a boolean or an integer.
func settings(p any) []setting {
	v := reflect.ValueOf(p)
	if v.Kind() != reflect.Pointer || v.Elem().Kind() != reflect.Struct {
		return nil
	}
	v = v.Elem()

	var s []setting
	for i := range v.NumField() {
		f := v.Type().Field(i)
		key, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if !f.IsExported() || key == "" || key == "-" {
			continue
		}
		switch f.Type.Kind() {
		case reflect.String, reflect.Bool, reflect.Int, reflect.Int64:
			s = append(s, setting{
				key:   key,
				env:   envPrefix + strings.ToUpper(key),
				value: v.Field(i),
			})
		}
	}

	return s
}

// set parses s according to the type of the setting and stores it.
func (s setting) set(raw string) error {
	switch {
	case s.value.Kind() == reflect.String:
		s.value.SetString(raw)
	case s.value.Kind() == reflect.Bool:
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return errors.New("not a boolean")
		}
		s.value.SetBool(b)
	case s.value.Type() == reflect.TypeFor[time.Duration]():
		d, err := time.ParseDuration(raw)
		if err != nil {
			return errors.New("not a duration such as 30s")
		}
		s.value.SetInt(int64(d))
	default:
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return errors.New("not an integer")
		}
		s.value.SetInt(n)
	}

	return nil
}

// readSecret returns the content of the file at path without surrounding
// whitespace, so that a trailing newline is not part of the secret.
func readSecret(path string) (string, error) {
	path = filepath.Clean(path)

	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	warnPermissions(path)

	return strings.TrimSpace(string(data)), nil
}

// warnPermissions logs a warning if the file holding credentials at path can
// be accessed by users other than its owner.
func warnPermissions(path string) {
	if runtime.GOOS == "windows" {
		return
	}
	if fi, err := os.Stat(path); err == nil && exposed(fi.Mode()) {
		log.Printf("warning: %s holds credentials and is accessible by other users (mode %04o), consider chmod 600", path, fi.Mode().Perm())
	}
}

// exposed reports whether a file of the given mode can be accessed by users
// other than its owner.
func exposed(mode os.FileMode) bool {
	return mode.Perm()&0o077 != 0
}

// loadEnv sets the settings of the provider p from the environment. A setting
// named key in the JSON configuration is read from the environment variable
// CDH_KEY, or from the file named by CDH_KEY_FILE. The latter keeps secrets
// out of the environment and works with systemd credentials and container
// secrets. The values are never logged.
func loadEnv(p any) error {
	for _, s := range settings(p) {
		raw, ok := os.LookupEnv(s.env)
		path, okFile := os.LookupEnv(s.env + envFileSuffix)

		switch {
		case ok && okFile:
			return fmt.Errorf("both %s and %s%s are set", s.env, s.env, envFileSuffix)
		case okFile:
			var err error
			if raw, err = readSecret(path); err != nil {
				return fmt.Errorf("reading %s%s: %w", s.env, envFileSuffix, err)
			}
		case !ok:
			continue
		}

		if err := s.set(raw); err != nil {
			// The value is left out on purpose: it may be a secret.
			return fmt.Errorf("%s: %w", s.env, err)
		}
	}

	return nil
}

// envNames returns the names of the environment variables read by loadEnv
// for the provider p.
func envNames(p any) []string {
	var names []string
	for _, s := range settings(p) {
		names = append(names, s.env)
	}
	return names
}
