package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/libdns/desec"
	"github.com/libdns/googleclouddns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func TestProviderNames(t *testing.T) {
	names := providerNames()

	assert.IsIncreasing(t, names)
	assert.Contains(t, names, defaultProvider)
	for _, n := range names {
		assert.NotNil(t, providers[n](), n)
	}
}

func TestNewProvider(t *testing.T) {
	t.Run("Config", func(t *testing.T) {
		p, err := newProvider("desec", writeFile(t, `{"token": "secret"}`), "")

		require.NoError(t, err)
		require.IsType(t, &desec.Provider{}, p)
		assert.Equal(t, "secret", p.(*desec.Provider).Token)
	})

	t.Run("EnvironmentOverridesConfig", func(t *testing.T) {
		t.Setenv("CDH_TOKEN", "from-env")

		p, err := newProvider("desec", writeFile(t, `{"token": "from-file"}`), "")

		require.NoError(t, err)
		assert.Equal(t, "from-env", p.(*desec.Provider).Token)
	})

	t.Run("InvalidEnvironment", func(t *testing.T) {
		t.Setenv("CDH_MAX_RETRIES", "many")

		_, err := newProvider("route53", "", "")

		assert.ErrorContains(t, err, "CDH_MAX_RETRIES")
	})

	t.Run("NoConfig", func(t *testing.T) {
		p, err := newProvider("route53", "", "")

		require.NoError(t, err)
		assert.NotNil(t, p)
	})

	t.Run("KeyFile", func(t *testing.T) {
		key := writeFile(t, `{"type": "service_account", "project_id": "project"}`)

		p, err := newProvider("googleclouddns", "", key)

		require.NoError(t, err)
		require.IsType(t, &googleclouddns.Provider{}, p)
		assert.Equal(t, "project", p.(*googleclouddns.Provider).Project)
		assert.Equal(t, key, p.(*googleclouddns.Provider).ServiceAccountJSON)
	})

	t.Run("KeyFileKeepsConfiguredProject", func(t *testing.T) {
		key := writeFile(t, `{"project_id": "project"}`)

		p, err := newProvider("googleclouddns", writeFile(t, `{"gcp_project": "other"}`), key)

		require.NoError(t, err)
		assert.Equal(t, "other", p.(*googleclouddns.Provider).Project)
	})

	t.Run("KeyFileWithoutProject", func(t *testing.T) {
		_, err := newProvider("googleclouddns", "", writeFile(t, `{}`))

		assert.ErrorContains(t, err, "project_id")
	})

	t.Run("MissingKeyFile", func(t *testing.T) {
		_, err := newProvider("googleclouddns", "", filepath.Join(t.TempDir(), "missing.json"))

		assert.Error(t, err)
	})

	t.Run("KeyFileWithOtherProvider", func(t *testing.T) {
		_, err := newProvider("desec", "", "key.json")

		assert.Error(t, err)
	})

	t.Run("UnknownProvider", func(t *testing.T) {
		_, err := newProvider("nope", "", "")

		assert.ErrorContains(t, err, "unknown DNS provider")
	})

	t.Run("UnknownField", func(t *testing.T) {
		_, err := newProvider("desec", writeFile(t, `{"tokne": "secret"}`), "")

		assert.Error(t, err)
	})

	t.Run("MissingConfig", func(t *testing.T) {
		_, err := newProvider("desec", filepath.Join(t.TempDir(), "missing.json"), "")

		assert.Error(t, err)
	})
}
