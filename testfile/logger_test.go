package testfile

import "testing"

func TestInitDevelopmentLogger(t *testing.T) {
	if err := Init(true); err != nil {
		t.Fatalf("expected development logger initialization to succeed: %v", err)
	}

	if Log == nil {
		t.Fatal("expected global logger to be initialized")
	}

	Sync()
}

func TestInitProductionLogger(t *testing.T) {
	if err := Init(false); err != nil {
		t.Fatalf("expected production logger initialization to succeed: %v", err)
	}

	if Log == nil {
		t.Fatal("expected global logger to be initialized")
	}

	Sync()
}

func TestSyncWithoutLogger(t *testing.T) {
	previousLogger := Log
	Log = nil

	Sync()

	Log = previousLogger
}
