package ims

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeMediaRouteManager struct {
	mu                     sync.Mutex
	acquired               []string
	released               []string
	acquireFailure         map[string]error
	acquireEndpointFailure map[string]error
	releaseFailure         map[string]error
}

func (manager *fakeMediaRouteManager) AcquireMediaRoute(
	_ context.Context,
	destination net.IP,
	sourcePort uint16,
	destinationPort uint16,
) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.acquired = append(
		manager.acquired,
		fmt.Sprintf("%s:%d/%d", destination, sourcePort, destinationPort),
	)
	if err := manager.acquireEndpointFailure[fmt.Sprintf("%s:%d/%d", destination, sourcePort, destinationPort)]; err != nil {
		return err
	}
	return manager.acquireFailure[destination.String()]
}

func TestRTPMediaManagesRemoteRouteAcrossSDPChanges(t *testing.T) {
	manager := &fakeMediaRouteManager{}
	media, err := newRTPMedia(net.IPv4(127, 0, 0, 1), manager)
	if err != nil {
		t.Fatal(err)
	}
	first := []byte("v=0\r\nc=IN IP4 127.0.0.2\r\nm=audio 4000 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\n")
	if err := media.configureRemote(first); err != nil {
		t.Fatal(err)
	}
	// A final answer on the same media host must still be revalidated. The
	// manager's acquire/release pair leaves one route reference outstanding.
	final := []byte("v=0\r\nc=IN IP4 127.0.0.2\r\nm=audio 4002 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n")
	if err := media.configureRemote(final); err != nil {
		t.Fatal(err)
	}
	second := []byte("v=0\r\nc=IN IP4 127.0.0.3\r\nm=audio 5000 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\n")
	if err := media.configureRemote(second); err != nil {
		t.Fatal(err)
	}
	if err := media.Close(); err != nil {
		t.Fatal(err)
	}
	if err := media.Close(); err != nil {
		t.Fatal(err)
	}

	manager.mu.Lock()
	defer manager.mu.Unlock()
	if len(manager.acquired) != 3 {
		t.Fatalf("route acquisitions = %#v, want early/final/re-INVITE", manager.acquired)
	}
	wantReleased := []string{"127.0.0.2", "127.0.0.2", "127.0.0.3"}
	if fmt.Sprint(manager.released) != fmt.Sprint(wantReleased) {
		t.Fatalf("route releases = %#v, want %#v", manager.released, wantReleased)
	}
}

func TestRTPMediaKeepsPreviousEndpointWhenRouteSwitchFails(t *testing.T) {
	manager := &fakeMediaRouteManager{
		releaseFailure: map[string]error{"127.0.0.2": errors.New("route delete failed")},
	}
	media, err := newRTPMedia(net.IPv4(127, 0, 0, 1), manager)
	if err != nil {
		t.Fatal(err)
	}
	defer media.Close()
	first := []byte("v=0\r\nc=IN IP4 127.0.0.2\r\nm=audio 4000 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\n")
	if err := media.configureRemote(first); err != nil {
		t.Fatal(err)
	}
	second := []byte("v=0\r\nc=IN IP4 127.0.0.3\r\nm=audio 5000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n")
	if err := media.configureRemote(second); err == nil {
		t.Fatal("route-release failure unexpectedly completed endpoint switch")
	}
	media.mu.RLock()
	remote, codec := cloneUDPAddress(media.remote), media.codec
	media.mu.RUnlock()
	if remote == nil || !remote.IP.Equal(net.IPv4(127, 0, 0, 2)) || remote.Port != 4000 || codec != "PCMA" {
		t.Fatalf("remote after failed switch = %#v codec=%q", remote, codec)
	}

	manager.mu.Lock()
	if got := manager.released; len(got) != 2 || got[0] != "127.0.0.2" || got[1] != "127.0.0.3" {
		manager.mu.Unlock()
		t.Fatalf("switch rollback releases = %#v", got)
	}
	delete(manager.releaseFailure, "127.0.0.2")
	manager.mu.Unlock()
}

func TestRTPMediaCloseRetriesFailedRouteRelease(t *testing.T) {
	releaseErr := errors.New("route delete failed")
	manager := &fakeMediaRouteManager{
		releaseFailure: map[string]error{"127.0.0.2": releaseErr},
	}
	media, err := newRTPMedia(net.IPv4(127, 0, 0, 1), manager)
	if err != nil {
		t.Fatal(err)
	}
	sdp := []byte("v=0\r\nc=IN IP4 127.0.0.2\r\nm=audio 4000 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\n")
	if err := media.configureRemote(sdp); err != nil {
		t.Fatal(err)
	}
	if err := media.Close(); !errors.Is(err, releaseErr) {
		t.Fatalf("first Close() error = %v, want %v", err, releaseErr)
	}
	manager.mu.Lock()
	delete(manager.releaseFailure, "127.0.0.2")
	manager.mu.Unlock()
	if err := media.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	media.routeMu.Lock()
	defer media.routeMu.Unlock()
	if len(media.routeRefs) != 0 {
		t.Fatalf("route refs after retry = %#v", media.routeRefs)
	}
}

func TestRTPMediaTracksBothRoutesWhenSwitchAndRollbackReleaseFail(t *testing.T) {
	manager := &fakeMediaRouteManager{
		releaseFailure: map[string]error{
			"127.0.0.2": errors.New("old route delete failed"),
			"127.0.0.3": errors.New("new route rollback failed"),
		},
	}
	media, err := newRTPMedia(net.IPv4(127, 0, 0, 1), manager)
	if err != nil {
		t.Fatal(err)
	}
	first := []byte("v=0\r\nc=IN IP4 127.0.0.2\r\nm=audio 4000 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\n")
	second := []byte("v=0\r\nc=IN IP4 127.0.0.3\r\nm=audio 5000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n")
	if err := media.configureRemote(first); err != nil {
		t.Fatal(err)
	}
	if err := media.configureRemote(second); err == nil {
		t.Fatal("route switch unexpectedly succeeded")
	}
	media.routeMu.Lock()
	if len(media.routeRefs) != 2 {
		media.routeMu.Unlock()
		t.Fatalf("route refs after failed switch = %#v, want old and new", media.routeRefs)
	}
	media.routeMu.Unlock()
	manager.mu.Lock()
	manager.releaseFailure = nil
	manager.mu.Unlock()
	if err := media.Close(); err != nil {
		t.Fatal(err)
	}
	media.routeMu.Lock()
	defer media.routeMu.Unlock()
	if len(media.routeRefs) != 0 {
		t.Fatalf("route refs after Close = %#v", media.routeRefs)
	}
}

func TestRTPMediaSymmetricPortLearningRequiresValidAuthorizedRTP(t *testing.T) {
	manager := &fakeMediaRouteManager{acquireEndpointFailure: make(map[string]error)}
	media, err := newRTPMedia(net.IPv4(127, 0, 0, 1), manager)
	if err != nil {
		t.Fatal(err)
	}
	defer media.Close()
	sdp := []byte("v=0\r\nc=IN IP4 127.0.0.1\r\nm=audio 4000 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\n")
	if err := media.configureRemote(sdp); err != nil {
		t.Fatal(err)
	}
	sender, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	sourcePort := sender.LocalAddr().(*net.UDPAddr).Port
	destination := media.conn.LocalAddr().(*net.UDPAddr)

	if _, err := sender.WriteToUDP([]byte{0x80, 0x08}, destination); err != nil {
		t.Fatal(err)
	}
	time.Sleep(25 * time.Millisecond)
	manager.mu.Lock()
	acquiredAfterMalformed := len(manager.acquired)
	manager.mu.Unlock()
	if acquiredAfterMalformed != 1 {
		t.Fatalf("malformed RTP triggered route authorization: %#v", manager.acquired)
	}

	endpoint := fmt.Sprintf("127.0.0.1:%d/%d", destination.Port, sourcePort)
	manager.mu.Lock()
	manager.acquireEndpointFailure[endpoint] = errors.New("outside traffic selector")
	manager.mu.Unlock()
	packet := make([]byte, 13)
	packet[0], packet[1] = 0x80, 8
	if _, err := sender.WriteToUDP(packet, destination); err != nil {
		t.Fatal(err)
	}
	waitForRTPTest(t, func() bool {
		manager.mu.Lock()
		defer manager.mu.Unlock()
		return len(manager.acquired) >= 2
	})
	media.mu.RLock()
	remotePort := media.remote.Port
	media.mu.RUnlock()
	if remotePort != 4000 {
		t.Fatalf("unauthorized symmetric RTP port was learned: %d", remotePort)
	}

	manager.mu.Lock()
	delete(manager.acquireEndpointFailure, endpoint)
	manager.mu.Unlock()
	if _, err := sender.WriteToUDP(packet, destination); err != nil {
		t.Fatal(err)
	}
	waitForRTPTest(t, func() bool {
		media.mu.RLock()
		defer media.mu.RUnlock()
		return media.remote.Port == sourcePort
	})
	media.routeMu.Lock()
	defer media.routeMu.Unlock()
	if len(media.routeRefs) != 1 {
		t.Fatalf("route refs after authorized port learning = %#v, want one", media.routeRefs)
	}
}

func TestRTPMediaRejectsStaleNegotiationSnapshotDuringPortLearning(t *testing.T) {
	manager := &fakeMediaRouteManager{}
	media, err := newRTPMedia(net.IPv4(127, 0, 0, 1), manager)
	if err != nil {
		t.Fatal(err)
	}
	defer media.Close()
	first := []byte("v=0\r\nc=IN IP4 127.0.0.2\r\nm=audio 4000 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\n")
	if err := media.configureRemote(first); err != nil {
		t.Fatal(err)
	}
	stale := media.negotiationSnapshot()
	second := []byte("v=0\r\nc=IN IP4 127.0.0.2\r\nm=audio 5000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n")
	if err := media.configureRemote(second); err != nil {
		t.Fatal(err)
	}

	// This is the exact receive/re-INVITE interleaving: validation used the
	// first SDP, while authorization runs after the second SDP was committed.
	if media.authorizeRTPSource(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 4500}, stale) {
		t.Fatal("packet from the previous negotiation changed the new endpoint")
	}
	current := media.negotiationSnapshot()
	if current.remote.Port != 5000 || current.codec != "PCMU" || current.payloadType != 0 {
		t.Fatalf("current negotiation was changed by stale RTP: %#v", current)
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if len(manager.acquired) != 2 {
		t.Fatalf("stale RTP triggered route authorization: %#v", manager.acquired)
	}
}

func TestRTPMediaRejectsMalformedStructureBeforePortAuthorization(t *testing.T) {
	manager := &fakeMediaRouteManager{}
	media, err := newRTPMedia(net.IPv4(127, 0, 0, 1), manager)
	if err != nil {
		t.Fatal(err)
	}
	defer media.Close()
	sdp := []byte("v=0\r\nc=IN IP4 127.0.0.1\r\nm=audio 4000 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\n")
	if err := media.configureRemote(sdp); err != nil {
		t.Fatal(err)
	}
	packet := func(first byte, payload ...byte) []byte {
		result := make([]byte, 12+len(payload))
		result[0], result[1] = first, 8
		copy(result[12:], payload)
		return result
	}
	malformed := [][]byte{
		packet(0x81),          // one CSRC is declared but absent
		packet(0x90, 0, 0, 0), // extension header is truncated
		packet(0xa0, 0),       // padding bit with a zero padding length
		packet(0xa0, 0, 3),    // padding exceeds the payload section
		packet(0xa0, 1),       // padding consumes the entire payload
	}
	source := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}
	for _, candidate := range malformed {
		media.handleRTPPacket(candidate, source)
	}

	current := media.negotiationSnapshot()
	if current.remote.Port != 4000 {
		t.Fatalf("malformed RTP changed symmetric port to %d", current.remote.Port)
	}
	if len(media.downlink) != 0 {
		t.Fatalf("malformed RTP delivered %d audio packets", len(media.downlink))
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if len(manager.acquired) != 1 {
		t.Fatalf("malformed RTP triggered route authorization: %#v", manager.acquired)
	}
}

func TestParseRTPPayloadHandlesCSRCHeaderExtensionAndPadding(t *testing.T) {
	extended := make([]byte, 25)
	extended[0], extended[1] = 0x91, 8 // V=2, X=1, CC=1
	extended[18], extended[19] = 0, 1  // one 32-bit extension word
	extended[24] = 0xd5
	payload, ok := parseRTPPayload(extended, 8)
	if !ok || len(payload) != 1 || payload[0] != 0xd5 {
		t.Fatalf("extended RTP payload = %x/%v, want d5/true", payload, ok)
	}

	padded := make([]byte, 15)
	padded[0], padded[1] = 0xa0, 8 // V=2, P=1
	padded[12], padded[13], padded[14] = 0x2a, 0, 2
	payload, ok = parseRTPPayload(padded, 8)
	if !ok || len(payload) != 1 || payload[0] != 0x2a {
		t.Fatalf("padded RTP payload = %x/%v, want 2a/true", payload, ok)
	}
}

func waitForRTPTest(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("timed out waiting for RTP state change")
}

func (manager *fakeMediaRouteManager) ReleaseMediaRoute(
	_ context.Context,
	destination net.IP,
) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	key := destination.String()
	manager.released = append(manager.released, key)
	return manager.releaseFailure[key]
}

func TestRTPMediaCarriesPCMOverPCMA(t *testing.T) {
	left, err := newRTPMedia(net.IPv4(127, 0, 0, 1))
	if err != nil {
		t.Fatal(err)
	}
	defer left.Close()
	right, err := newRTPMedia(net.IPv4(127, 0, 0, 1))
	if err != nil {
		t.Fatal(err)
	}
	defer right.Close()
	if err := left.configureRemote(right.offerSDP(net.IPv4(127, 0, 0, 1))); err != nil {
		t.Fatal(err)
	}
	if err := right.configureRemote(left.answerSDP(net.IPv4(127, 0, 0, 1))); err != nil {
		t.Fatal(err)
	}
	want := make([]int16, rtpPacketSamples)
	for index := range want {
		want[index] = int16(9000 * math.Sin(float64(index)*2*math.Pi/40))
	}
	if err := left.WritePCM(want); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := right.ReadPCM(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("received %d samples, want %d", len(got), len(want))
	}
	for index := range got {
		if difference := math.Abs(float64(got[index]) - float64(want[index])); difference > 700 {
			t.Fatalf("sample %d difference %.0f exceeds G.711 tolerance", index, difference)
		}
	}
}

func TestParseAudioSDPRejectsMissingEndpoint(t *testing.T) {
	if _, _, _, _, err := parseAudioSDP([]byte("v=0\r\nm=audio 0 RTP/AVP 8\r\n")); err == nil {
		t.Fatal("expected unusable SDP error")
	}
}

func TestRTPMediaOfferAdvertisesOnlyImplementedVoiceCodecs(t *testing.T) {
	media, err := newRTPMedia(net.IPv4(127, 0, 0, 1))
	if err != nil {
		t.Fatal(err)
	}
	defer media.Close()
	offer := string(media.offerSDP(net.IPv4(127, 0, 0, 1)))
	if strings.Contains(offer, "AMR") {
		t.Fatalf("offer advertises an unimplemented codec:\n%s", offer)
	}
	if strings.Contains(strings.ToLower(offer), "telephone-event") {
		t.Fatalf("offer advertises unimplemented RTP DTMF:\n%s", offer)
	}
	if !strings.Contains(offer, "PCMA/8000") || !strings.Contains(offer, "PCMU/8000") {
		t.Fatalf("offer does not advertise both implemented G.711 codecs:\n%s", offer)
	}
}

func TestRTPMediaSkipsUnsupportedRemoteCodec(t *testing.T) {
	media, err := newRTPMedia(net.IPv4(127, 0, 0, 1))
	if err != nil {
		t.Fatal(err)
	}
	defer media.Close()
	sdp := []byte("v=0\r\nc=IN IP4 127.0.0.1\r\nm=audio 4000 RTP/AVP 104 8\r\na=rtpmap:104 AMR-WB/16000\r\na=rtpmap:8 PCMA/8000\r\n")
	if err := media.configureRemote(sdp); err != nil {
		t.Fatal(err)
	}
	if media.Codec() != "PCMA" || media.payloadType != 8 {
		t.Fatalf("negotiated codec = %q/%d, want PCMA/8", media.Codec(), media.payloadType)
	}
}

func TestRTPMediaRejectsAMROnlyRemoteOffer(t *testing.T) {
	media, err := newRTPMedia(net.IPv4(127, 0, 0, 1))
	if err != nil {
		t.Fatal(err)
	}
	defer media.Close()
	sdp := []byte("v=0\r\nc=IN IP4 127.0.0.1\r\nm=audio 4000 RTP/AVP 104\r\na=rtpmap:104 AMR-WB/16000\r\n")
	if err := media.configureRemote(sdp); err == nil {
		t.Fatal("AMR-only offer unexpectedly succeeded")
	}
}
