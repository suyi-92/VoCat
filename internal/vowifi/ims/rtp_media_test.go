package ims

import (
	"context"
	"math"
	"net"
	"strings"
	"testing"
	"time"
)

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
