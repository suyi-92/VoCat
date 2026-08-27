package store

import (
	"context"
	"testing"
)

func TestVLESSUpstreamSecretPreservationAndLegacyCompatibility(t *testing.T) {
	database, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })

	value := UpstreamProxy{
		ID:       "managed-vless",
		Name:     "Managed VLESS",
		Addr:     "edge.example.com:443",
		Password: "11111111-2222-4333-8444-555555555555",
		Enabled:  true,
		Extra:    []byte(`{"type":"vless","udp":true}`),
	}
	if err := database.UpsertUpstreamProxy(context.Background(), value); err != nil {
		t.Fatal(err)
	}
	stored, err := database.UpstreamProxy(context.Background(), value.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Protocol() != UpstreamProtocolVLESS || stored.Redacted().Password != SecretMask {
		t.Fatalf("stored VLESS = %+v", stored)
	}

	stored.Name = "Updated VLESS"
	stored.Password = SecretMask
	if err := database.UpsertUpstreamProxy(context.Background(), stored); err != nil {
		t.Fatal(err)
	}
	updated, err := database.UpstreamProxy(context.Background(), value.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Password != value.Password || updated.Name != "Updated VLESS" {
		t.Fatalf("updated VLESS = %+v", updated)
	}

	legacy := UpstreamProxy{ID: "legacy", Name: "Legacy", Addr: "127.0.0.1:1080", Enabled: true}
	if err := database.UpsertUpstreamProxy(context.Background(), legacy); err != nil {
		t.Fatal(err)
	}
	legacy, err = database.UpstreamProxy(context.Background(), legacy.ID)
	if err != nil {
		t.Fatal(err)
	}
	if legacy.Protocol() != UpstreamProtocolSOCKS5 {
		t.Fatalf("legacy protocol = %q", legacy.Protocol())
	}
}

func TestVLESSUpstreamRequiresUUID(t *testing.T) {
	database, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	err = database.UpsertUpstreamProxy(context.Background(), UpstreamProxy{
		ID: "missing-secret", Name: "Missing", Addr: "edge.example.com:443", Enabled: true,
		Extra: []byte(`{"type":"vless","udp":true}`),
	})
	if err == nil {
		t.Fatal("UpsertUpstreamProxy accepted VLESS without a UUID")
	}
}
