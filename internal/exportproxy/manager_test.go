package exportproxy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"vocat/internal/store"
)

func TestManagerPersistsAndDeletesDisabledConfig(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, filepath.Join(t.TempDir(), "vocat.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.UpsertDevice(ctx, store.Device{ID: "modem-1", Name: "modem-1", Interface: "wwan0"}); err != nil {
		t.Fatal(err)
	}
	manager, err := New(ctx, database, slog.New(slog.NewTextHandler(io.Discard, nil)), "")
	if err != nil {
		t.Fatal(err)
	}
	created, err := manager.Create(ctx, Config{DeviceID: "modem-1", Mode: "socks5", ListenHost: "127.0.0.1", ListenPort: 0})
	if err != nil {
		t.Fatal(err)
	}
	if created.ID == "" || created.Interface != "wwan0" {
		t.Fatalf("created = %+v", created)
	}
	configs, err := manager.Configs()
	if err != nil || len(configs) != 1 {
		t.Fatalf("configs = %+v, %v", configs, err)
	}
	if err := manager.DeleteAllAndDisable(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Configs(); !errors.Is(err, ErrDisabled) {
		t.Fatalf("Configs after disable = %v", err)
	}
	if _, err := database.AppSetting(ctx, SettingKey); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("setting remains: %v", err)
	}
}

func TestManagerRequiresRoamingDataForEnabledProxy(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, filepath.Join(t.TempDir(), "vocat.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.UpsertDevice(ctx, store.Device{ID: "modem-1", Name: "modem-1", Interface: "wwan0"}); err != nil {
		t.Fatal(err)
	}
	manager, err := New(ctx, database, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	_, err = manager.Create(ctx, Config{DeviceID: "modem-1", Mode: "socks5", ListenHost: "127.0.0.1", ListenPort: 1080, Enabled: true})
	if err == nil {
		t.Fatal("enabled proxy was accepted while roaming data was disabled")
	}
}

func TestManagerEnabledConfigForDevice(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, filepath.Join(t.TempDir(), "vocat.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.UpsertDevice(ctx, store.Device{ID: "modem-1", Name: "modem-1", Interface: "wwan0", NetworkEnabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := database.UpsertDevice(ctx, store.Device{ID: "modem-2", Name: "modem-2", Interface: "wwan1", NetworkEnabled: true}); err != nil {
		t.Fatal(err)
	}
	manager, err := New(ctx, database, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if _, ok := manager.EnabledConfigForDevice("modem-1"); ok {
		t.Fatal("reported an enabled config before any was created")
	}
	// A disabled config bound to modem-1 must not count.
	if _, err := manager.Create(ctx, Config{DeviceID: "modem-1", Mode: "socks5", ListenHost: "127.0.0.1", ListenPort: 0}); err != nil {
		t.Fatal(err)
	}
	if _, ok := manager.EnabledConfigForDevice("modem-1"); ok {
		t.Fatal("disabled config counted as enabled")
	}
	// An enabled config bound to modem-2 counts only for modem-2. The listener start
	// is Linux-only, so the config is created disabled and flipped on in memory to
	// exercise the query without binding a port.
	created, err := manager.Create(ctx, Config{DeviceID: "modem-2", Mode: "socks5", ListenHost: "127.0.0.1", ListenPort: 0, AuthEnabled: true, Username: "u", Password: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	manager.mu.Lock()
	for index := range manager.configs {
		if manager.configs[index].ID == created.ID {
			manager.configs[index].Enabled = true
		}
	}
	manager.mu.Unlock()
	if _, ok := manager.EnabledConfigForDevice("modem-1"); ok {
		t.Fatal("config bound to another device counted")
	}
	found, ok := manager.EnabledConfigForDevice("modem-2")
	if !ok {
		t.Fatal("enabled config not found for its device")
	}
	if found.Password != PasswordMask {
		t.Fatalf("password not redacted: %+v", found)
	}
}
