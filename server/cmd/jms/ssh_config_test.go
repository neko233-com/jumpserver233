package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
)

func TestSSHConfigSyncPreservesUserConfigAndIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "config")
	original := []byte("Host personal\n  HostName example.test\nHost *\n  ServerAliveInterval 30\n")
	if err := os.WriteFile(config, original, 0600); err != nil {
		t.Fatal(err)
	}
	assets := []sessionclient.SSHConfigAsset{
		{Name: "Build Mac", Protocol: "ssh", Accounts: []sessionclient.SSHConfigAccount{{ID: "asset-123456", Name: "gamer", Active: true, Permissions: []string{"connect"}}}},
		{Name: "disabled", Accounts: []sessionclient.SSHConfigAccount{{ID: "asset-disabled", Active: false, Permissions: []string{"connect"}}}},
		{Name: "view only", Accounts: []sessionclient.SSHConfigAccount{{ID: "asset-view", Active: true, Permissions: []string{"view"}}}},
		{Name: "other protocol", Protocol: "rdp", Accounts: []sessionclient.SSHConfigAccount{{ID: "asset-rdp", Active: true, Permissions: []string{"connect"}}}},
	}
	var out bytes.Buffer
	run := func() error {
		return importSSHConfig(config, "https://bastion.example", "bastion.example", 2222, "operator", "", assets, false, &out)
	}
	if err := run(); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(first, original) || !bytes.Contains(first, []byte("# BEGIN ")) {
		t.Fatalf("user config lost: %s", first)
	}
	managed := first
	if !bytes.Contains(managed, []byte("User operator#asset-123456")) || bytes.Contains(managed, []byte("asset-disabled")) || bytes.Contains(managed, []byte("asset-view")) || bytes.Contains(managed, []byte("asset-rdp")) {
		t.Fatalf("unexpected entries %s", managed)
	}
	if err = run(); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(config)
	if !bytes.Equal(first, second) {
		t.Fatal("repeat import changed config")
	}
	assets = nil
	if err = run(); err == nil {
		t.Fatal("empty inventory must not erase existing aliases")
	}
	unchanged, _ := os.ReadFile(config)
	if !bytes.Equal(managed, unchanged) {
		t.Fatal("failed import changed managed file")
	}
}

func TestSSHConfigRejectsUnsafeIdentityBeforeWriting(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "config")
	assets := []sessionclient.SSHConfigAsset{{Accounts: []sessionclient.SSHConfigAccount{{ID: "bad\nHost injected", Active: true, Permissions: []string{"connect"}}}}}
	if err := importSSHConfig(config, "https://example.test", "example.test", 2222, "operator", "", assets, false, &bytes.Buffer{}); err == nil {
		t.Fatal("unsafe account id accepted")
	}
	if _, err := os.Stat(config); !os.IsNotExist(err) {
		t.Fatal("invalid inventory changed config")
	}
	assets[0].Accounts[0].ID = "asset-valid"
	if err := importSSHConfig(config, "https://example.test", "evil\nHost injected", 2222, "operator", "", assets, false, &bytes.Buffer{}); err == nil {
		t.Fatal("unsafe host accepted")
	}
}

func TestSSHConfigRefusesMalformedManagedBlock(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "config")
	assets := []sessionclient.SSHConfigAsset{{Name: "server", Accounts: []sessionclient.SSHConfigAccount{{ID: "asset-valid", Active: true, Permissions: []string{"connect"}}}}}
	var out bytes.Buffer
	if err := importSSHConfig(config, "https://example.test", "example.test", 2222, "operator", "", assets, false, &out); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(string(data), "# END ", "# DAMAGED ", 1)
	if err := os.WriteFile(config, []byte(changed), 0600); err != nil {
		t.Fatal(err)
	}
	if err := importSSHConfig(config, "https://example.test", "example.test", 2222, "operator", "", assets, false, &out); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("expected collision error: %v", err)
	}
	data, _ = os.ReadFile(config)
	if string(data) != changed {
		t.Fatal("foreign file overwritten")
	}
}
