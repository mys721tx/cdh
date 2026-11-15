package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/libdns/desec"
	"github.com/libdns/route53"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnvNames(t *testing.T) {
	assert.Equal(t, []string{"CDH_TOKEN"}, envNames(new(desec.Provider)))
	assert.Equal(t, []string{"CDH_GCP_PROJECT", "CDH_GCP_APPLICATION_DEFAULT"}, envNames(providers["googleclouddns"]()))
	assert.Contains(t, envNames(new(route53.Provider)), "CDH_SECRET_ACCESS_KEY")
	assert.NotContains(t, envNames(new(route53.Provider)), "CDH_-", "fields without a JSON name are not settings")
	assert.Empty(t, envNames(desec.Provider{}), "settings need a pointer")

	for name, mk := range providers {
		assert.NotEmpty(t, envNames(mk()), name)
	}
}

func TestLoadEnv(t *testing.T) {
	t.Run("Value", func(t *testing.T) {
		t.Setenv("CDH_TOKEN", "secret")
		p := new(desec.Provider)

		require.NoError(t, loadEnv(p))
		assert.Equal(t, "secret", p.Token)
	})

	t.Run("File", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "token")
		require.NoError(t, os.WriteFile(path, []byte("secret\n"), 0o600))
		t.Setenv("CDH_TOKEN_FILE", path)
		p := new(desec.Provider)

		require.NoError(t, loadEnv(p))
		assert.Equal(t, "secret", p.Token, "the trailing newline is not part of the secret")
	})

	t.Run("Unset", func(t *testing.T) {
		p := &desec.Provider{Token: "configured"}

		require.NoError(t, loadEnv(p))
		assert.Equal(t, "configured", p.Token)
	})

	t.Run("ValueAndFile", func(t *testing.T) {
		t.Setenv("CDH_TOKEN", "secret")
		t.Setenv("CDH_TOKEN_FILE", "token")

		assert.ErrorContains(t, loadEnv(new(desec.Provider)), "both")
	})

	t.Run("MissingFile", func(t *testing.T) {
		t.Setenv("CDH_TOKEN_FILE", filepath.Join(t.TempDir(), "missing"))

		assert.ErrorContains(t, loadEnv(new(desec.Provider)), "CDH_TOKEN_FILE")
	})

	t.Run("Types", func(t *testing.T) {
		t.Setenv("CDH_MAX_RETRIES", "3")
		t.Setenv("CDH_WAIT_FOR_ROUTE53_SYNC", "true")
		t.Setenv("CDH_ROUTE53_MAX_WAIT", "90s")
		p := new(route53.Provider)

		require.NoError(t, loadEnv(p))
		assert.Equal(t, 3, p.MaxRetries)
		assert.True(t, p.WaitForRoute53Sync)
		assert.Equal(t, 90*time.Second, p.Route53MaxWait)
	})

	for env, value := range map[string]string{
		"CDH_MAX_RETRIES":           "many",
		"CDH_WAIT_FOR_ROUTE53_SYNC": "maybe",
		"CDH_ROUTE53_MAX_WAIT":      "soon",
	} {
		t.Run("Invalid"+env, func(t *testing.T) {
			t.Setenv(env, value)

			err := loadEnv(new(route53.Provider))

			require.ErrorContains(t, err, env)
			assert.NotContains(t, err.Error(), value, "values are not echoed, they may be secrets")
		})
	}
}

func TestExposed(t *testing.T) {
	assert.False(t, exposed(0o600))
	assert.False(t, exposed(0o400))
	assert.True(t, exposed(0o640))
	assert.True(t, exposed(0o604))
}
