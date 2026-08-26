//go:build windows

package pcsc

import (
	"context"
	"encoding/hex"
	"os"
	"testing"
	"time"
)

// TestWindowsPCSCEUICCTransport is opt-in because ordinary CI has no smart
// card hardware. It performs only volatile ISO 7816 operations: open a logical
// channel, select the standard ISD-R application, and close the channel. It
// never downloads, enables, disables, deletes, or otherwise changes a profile.
func TestWindowsPCSCEUICCTransport(t *testing.T) {
	readerName := os.Getenv("VOCAT_PCSC_INTEGRATION_READER")
	if readerName == "" {
		t.Skip("set VOCAT_PCSC_INTEGRATION_READER to run the WinSCard/eUICC probe")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	service := New()
	session, err := service.OpenSession(ctx, Selector{ReaderName: readerName})
	if err != nil {
		t.Fatalf("OpenSession(%q): %v", readerName, err)
	}
	defer session.Close()

	channelReply, sw, err := session.Transmit(ctx, []byte{0x00, 0x70, 0x00, 0x00, 0x01})
	if err != nil || sw != 0x9000 || len(channelReply) != 1 {
		t.Fatalf("MANAGE CHANNEL = % X, %04X, %v", channelReply, sw, err)
	}
	channel := channelReply[0]
	defer func() {
		_, _, closeErr := session.Transmit(context.Background(), []byte{0x00, 0x70, 0x80, channel, 0x00})
		if closeErr != nil {
			t.Errorf("close logical channel %d: %v", channel, closeErr)
		}
	}()

	isdR, err := hex.DecodeString("A0000005591010FFFFFFFF8900000100")
	if err != nil {
		t.Fatal(err)
	}
	selectISDR := append([]byte{channel, 0xA4, 0x04, 0x00, byte(len(isdR))}, isdR...)
	response, sw, err := transmitWindowsIntegrationAPDU(ctx, session, selectISDR, channel)
	if err != nil || sw != 0x9000 {
		t.Fatalf("SELECT ISD-R = % X, %04X, %v", response, sw, err)
	}
	if len(response) > 0 {
		t.Logf("ISD-R FCI: % X", response)
	}
}

func transmitWindowsIntegrationAPDU(ctx context.Context, session *Session, command []byte, channel byte) ([]byte, uint16, error) {
	response, sw, err := session.Transmit(ctx, command)
	for continuation := 0; err == nil && sw>>8 == 0x61 && continuation < 24; continuation++ {
		more, nextSW, nextErr := session.Transmit(ctx, []byte{channel, 0xC0, 0x00, 0x00, byte(sw)})
		response = append(response, more...)
		sw, err = nextSW, nextErr
	}
	return response, sw, err
}
