package config

import (
	"github.com/stretchr/testify/require"
	"path/filepath"
	"testing"
)

func TestRuntimeLogsDefaultsAndBounds(t *testing.T) {
	clearConfigEnv(t)
	cfg, err := FromEnv()
	require.NoError(t, err)
	require.Equal(t, filepath.Join(cfg.DataDir, "logs"), cfg.LogDir)
	require.Equal(t, 10, cfg.LogMaxMB)
	require.Equal(t, 5, cfg.LogBackups)
	require.Equal(t, 14, cfg.LogDays)
	for _, name := range []string{"JMS_LOG_MAX_MB", "JMS_LOG_BACKUPS", "JMS_LOG_DAYS"} {
		for _, v := range []string{"0", "-1", "garbage", "9999"} {
			t.Run(name+v, func(t *testing.T) { t.Setenv(name, v); _, err := FromEnv(); require.Error(t, err) })
		}
	}
	t.Setenv("JMS_LOG_DIR", "-")
	t.Setenv("JMS_LOG_CONSOLE", "false")
	_, err = FromEnv()
	require.Error(t, err)
}
