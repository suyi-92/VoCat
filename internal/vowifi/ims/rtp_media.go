package ims

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	rtpClockRate     = 8000
	rtpPacketSamples = 160
	rtpRouteTimeout  = 5 * time.Second
)

type mediaRouteManager interface {
	AcquireMediaRoute(context.Context, net.IP, uint16, uint16) error
	ReleaseMediaRoute(context.Context, net.IP) error
}

type unavailableMediaRouteManager struct{}

func (unavailableMediaRouteManager) AcquireMediaRoute(
	context.Context,
	net.IP,
	uint16,
	uint16,
) error {
	return errors.New("ims: user-space tunnel does not expose dynamic media-route control")
}

func (unavailableMediaRouteManager) ReleaseMediaRoute(context.Context, net.IP) error {
	return nil
}

type rtpMedia struct {
	conn         *net.UDPConn
	routeManager mediaRouteManager
	routeMu      sync.Mutex
	routeIP      net.IP
	routeRefs    []net.IP

	mu          sync.RWMutex
	remote      *net.UDPAddr
	codec       string
	payloadType byte
	generation  uint64

	writeMu   sync.Mutex
	pending   []int16
	sequence  uint16
	timestamp uint32
	ssrc      uint32

	downlink chan []int16
	closed   chan struct{}
	close    sync.Once
	closeErr error
}

type rtpNegotiationSnapshot struct {
	remote      *net.UDPAddr
	codec       string
	payloadType byte
	generation  uint64
}

func newRTPMedia(local net.IP, routeManagers ...mediaRouteManager) (*rtpMedia, error) {
	address := &net.UDPAddr{IP: local, Port: 0}
	connection, err := net.ListenUDP("udp", address)
	if err != nil {
		return nil, fmt.Errorf("ims: open RTP socket: %w", err)
	}
	seed := make([]byte, 10)
	if _, err := io.ReadFull(cryptorand.Reader, seed); err != nil {
		_ = connection.Close()
		return nil, fmt.Errorf("ims: initialize RTP state: %w", err)
	}
	var routeManager mediaRouteManager
	if len(routeManagers) > 0 {
		routeManager = routeManagers[0]
	}
	media := &rtpMedia{
		conn: connection, sequence: binary.BigEndian.Uint16(seed[:2]),
		timestamp: binary.BigEndian.Uint32(seed[2:6]), ssrc: binary.BigEndian.Uint32(seed[6:]),
		downlink: make(chan []int16, 64), closed: make(chan struct{}), routeManager: routeManager,
	}
	go media.receive()
	return media, nil
}

func (media *rtpMedia) Codec() string {
	media.mu.RLock()
	defer media.mu.RUnlock()
	return media.codec
}

func (media *rtpMedia) ready() bool {
	media.mu.RLock()
	defer media.mu.RUnlock()
	return media.remote != nil && media.codec != ""
}

func (media *rtpMedia) offerSDP(local net.IP) []byte {
	return media.buildSDP(local, "8 0", []string{
		"a=rtpmap:8 PCMA/8000",
		"a=rtpmap:0 PCMU/8000",
	})
}

func (media *rtpMedia) answerSDP(local net.IP) []byte {
	media.mu.RLock()
	codec, payload := media.codec, media.payloadType
	media.mu.RUnlock()
	if codec == "" {
		return media.offerSDP(local)
	}
	return media.buildSDP(local, strconv.Itoa(int(payload)), []string{
		fmt.Sprintf("a=rtpmap:%d %s/8000", payload, codec),
	})
}

func (media *rtpMedia) buildSDP(local net.IP, formats string, attributes []string) []byte {
	if local == nil || local.IsUnspecified() {
		if udp, ok := media.conn.LocalAddr().(*net.UDPAddr); ok {
			local = udp.IP
		}
	}
	if local == nil || local.IsUnspecified() {
		local = net.IPv4zero
	}
	family := "IP4"
	if local.To4() == nil {
		family = "IP6"
	}
	port := media.conn.LocalAddr().(*net.UDPAddr).Port
	sessionID := time.Now().UnixNano()
	lines := []string{
		"v=0",
		fmt.Sprintf("o=- %d %d IN %s %s", sessionID, sessionID, family, local.String()),
		"s=VoCat",
		fmt.Sprintf("c=IN %s %s", family, local.String()),
		"t=0 0",
		fmt.Sprintf("m=audio %d RTP/AVP %s", port, formats),
	}
	if attributes == nil {
		lines = append(lines,
			"a=rtpmap:8 PCMA/8000",
			"a=rtpmap:0 PCMU/8000",
		)
	} else {
		lines = append(lines, attributes...)
	}
	lines = append(lines, "a=ptime:20", "a=sendrecv", "")
	return []byte(strings.Join(lines, "\r\n"))
}

func (media *rtpMedia) configureRemote(body []byte) error {
	address, port, formats, mappings, err := parseAudioSDP(body)
	if err != nil {
		return err
	}
	var codec string
	var payload byte
	for _, value := range formats {
		parsed, parseErr := strconv.Atoi(value)
		if parseErr != nil || parsed < 0 || parsed > 127 {
			continue
		}
		name := strings.ToUpper(mappings[parsed])
		if name == "" {
			switch parsed {
			case 0:
				name = "PCMU"
			case 8:
				name = "PCMA"
			case 100:
				continue
			default:
				name = fmt.Sprintf("PAYLOAD-%d", parsed)
			}
		}
		if name == "PCMA" || name == "PCMU" {
			codec, payload = name, byte(parsed)
			break
		}
	}
	if codec == "" {
		return errors.New("ims: remote SDP has no supported audio format (PCMA or PCMU required)")
	}
	address = append(net.IP(nil), address...)
	localPort := media.conn.LocalAddr().(*net.UDPAddr).Port
	if localPort < 1 || localPort > 65535 {
		return errors.New("ims: local RTP socket has an invalid port")
	}

	media.routeMu.Lock()
	defer media.routeMu.Unlock()
	select {
	case <-media.closed:
		return io.EOF
	default:
	}
	if err = media.acquireRouteReference(address, uint16(localPort), uint16(port)); err != nil {
		return fmt.Errorf("ims: authorize remote RTP route: %w", err)
	}
	oldRouteIP := append(net.IP(nil), media.routeIP...)

	if media.routeManager != nil && oldRouteIP != nil {
		releaseErr := media.releaseRouteReference(oldRouteIP)
		if releaseErr != nil {
			// The negotiated endpoint is committed only after its replacement
			// route is authorized and the previous reference is retired.
			rollbackErr := media.releaseRouteReference(address)
			return errors.Join(
				fmt.Errorf("ims: release previous RTP route: %w", releaseErr),
				wrapMediaRouteReleaseError("roll back new RTP route", rollbackErr),
			)
		}
	}
	media.routeIP = append(net.IP(nil), address...)
	media.mu.Lock()
	media.remote = &net.UDPAddr{IP: address, Port: port}
	media.codec = codec
	media.payloadType = payload
	media.generation++
	media.mu.Unlock()
	return nil
}

func (media *rtpMedia) acquireRouteReference(address net.IP, sourcePort, destinationPort uint16) error {
	if media.routeManager == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), rtpRouteTimeout)
	err := media.routeManager.AcquireMediaRoute(ctx, address, sourcePort, destinationPort)
	cancel()
	if err == nil {
		media.routeRefs = append(media.routeRefs, append(net.IP(nil), address...))
	}
	return err
}

func (media *rtpMedia) releaseRouteReference(address net.IP) error {
	if media.routeManager == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), rtpRouteTimeout)
	err := media.routeManager.ReleaseMediaRoute(ctx, address)
	cancel()
	if err != nil {
		return err
	}
	for index := len(media.routeRefs) - 1; index >= 0; index-- {
		if media.routeRefs[index].Equal(address) {
			media.routeRefs = append(media.routeRefs[:index], media.routeRefs[index+1:]...)
			break
		}
	}
	return nil
}

func wrapMediaRouteReleaseError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("ims: %s: %w", operation, err)
}

func cloneUDPAddress(address *net.UDPAddr) *net.UDPAddr {
	if address == nil {
		return nil
	}
	result := *address
	result.IP = append(net.IP(nil), address.IP...)
	return &result
}

func (media *rtpMedia) negotiationSnapshot() rtpNegotiationSnapshot {
	media.mu.RLock()
	defer media.mu.RUnlock()
	return rtpNegotiationSnapshot{
		remote:      cloneUDPAddress(media.remote),
		codec:       media.codec,
		payloadType: media.payloadType,
		generation:  media.generation,
	}
}

func (media *rtpMedia) negotiationMatchesLocked(expected rtpNegotiationSnapshot) bool {
	if media.generation != expected.generation || media.codec != expected.codec ||
		media.payloadType != expected.payloadType || media.remote == nil || expected.remote == nil {
		return false
	}
	return media.remote.IP.Equal(expected.remote.IP) && media.remote.Port == expected.remote.Port
}

func parseAudioSDP(body []byte) (net.IP, int, []string, map[int]string, error) {
	var sessionIP, mediaIP net.IP
	var port int
	var formats []string
	mappings := make(map[int]string)
	inAudio := false
	for _, raw := range strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "m="):
			fields := strings.Fields(strings.TrimPrefix(line, "m="))
			inAudio = len(fields) >= 4 && strings.EqualFold(fields[0], "audio") && strings.HasPrefix(strings.ToUpper(fields[2]), "RTP/AVP")
			if inAudio {
				port, _ = strconv.Atoi(strings.Split(fields[1], "/")[0])
				formats = append([]string(nil), fields[3:]...)
			}
		case strings.HasPrefix(line, "c="):
			fields := strings.Fields(strings.TrimPrefix(line, "c="))
			if len(fields) >= 3 {
				ip := net.ParseIP(strings.Split(fields[2], "/")[0])
				if inAudio {
					mediaIP = ip
				} else {
					sessionIP = ip
				}
			}
		case inAudio && strings.HasPrefix(strings.ToLower(line), "a=rtpmap:"):
			fields := strings.Fields(strings.TrimPrefix(line, "a=rtpmap:"))
			if len(fields) == 2 {
				pt, parseErr := strconv.Atoi(fields[0])
				if parseErr == nil {
					mappings[pt] = strings.Split(fields[1], "/")[0]
				}
			}
		}
	}
	if mediaIP == nil {
		mediaIP = sessionIP
	}
	if mediaIP == nil || port < 1 || port > 65535 || len(formats) == 0 {
		return nil, 0, nil, nil, errors.New("ims: remote SDP has no usable audio endpoint")
	}
	return mediaIP, port, formats, mappings, nil
}

func (media *rtpMedia) ReadPCM(ctx context.Context) ([]int16, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-media.closed:
		return nil, io.EOF
	case samples := <-media.downlink:
		return samples, nil
	}
}

func (media *rtpMedia) WritePCM(samples []int16) error {
	media.mu.RLock()
	var remote *net.UDPAddr
	if media.remote != nil {
		copy := *media.remote
		remote = &copy
	}
	codec, payload := media.codec, media.payloadType
	media.mu.RUnlock()
	if remote == nil || codec == "" {
		return errors.New("ims: RTP media is not negotiated")
	}
	media.writeMu.Lock()
	defer media.writeMu.Unlock()
	media.pending = append(media.pending, samples...)
	for len(media.pending) >= rtpPacketSamples {
		packet := make([]byte, 12+rtpPacketSamples)
		packet[0], packet[1] = 0x80, payload
		binary.BigEndian.PutUint16(packet[2:4], media.sequence)
		binary.BigEndian.PutUint32(packet[4:8], media.timestamp)
		binary.BigEndian.PutUint32(packet[8:12], media.ssrc)
		for index, sample := range media.pending[:rtpPacketSamples] {
			switch codec {
			case "PCMA":
				packet[12+index] = linearToALaw(sample)
			case "PCMU":
				packet[12+index] = linearToMuLaw(sample)
			default:
				return fmt.Errorf("ims: unsupported negotiated RTP codec %q", codec)
			}
		}
		if _, err := media.conn.WriteToUDP(packet, remote); err != nil {
			return fmt.Errorf("ims: send RTP: %w", err)
		}
		media.pending = media.pending[rtpPacketSamples:]
		media.sequence++
		media.timestamp += rtpPacketSamples
	}
	return nil
}

func (media *rtpMedia) receive() {
	packet := make([]byte, 2048)
	for {
		count, source, err := media.conn.ReadFromUDP(packet)
		if err != nil {
			return
		}
		media.handleRTPPacket(packet[:count], source)
	}
}

func (media *rtpMedia) handleRTPPacket(packet []byte, source *net.UDPAddr) {
	expected := media.negotiationSnapshot()
	if expected.remote == nil || source == nil || !expected.remote.IP.Equal(source.IP) ||
		(expected.codec != "PCMA" && expected.codec != "PCMU") {
		return
	}
	payload, ok := parseRTPPayload(packet, expected.payloadType)
	if !ok || !media.authorizeRTPSource(source, expected) {
		return
	}
	samples := make([]int16, len(payload))
	for index, encoded := range payload {
		switch expected.codec {
		case "PCMA":
			samples[index] = aLawToLinear(encoded)
		case "PCMU":
			samples[index] = muLawToLinear(encoded)
		}
	}
	select {
	case media.downlink <- samples:
	default:
		// Keep real-time behavior by dropping the oldest queued packet.
		select {
		case <-media.downlink:
		default:
		}
		select {
		case media.downlink <- samples:
		default:
		}
	}
}

func parseRTPPayload(packet []byte, payloadType byte) ([]byte, bool) {
	if len(packet) < 12 || packet[0]>>6 != 2 || packet[1]&0x7f != payloadType {
		return nil, false
	}
	header := 12 + int(packet[0]&0x0f)*4
	if header > len(packet) {
		return nil, false
	}
	if packet[0]&0x10 != 0 {
		if len(packet)-header < 4 {
			return nil, false
		}
		extensionWords := int(binary.BigEndian.Uint16(packet[header+2 : header+4]))
		if extensionWords > (len(packet)-header-4)/4 {
			return nil, false
		}
		header += 4 + extensionWords*4
	}
	payloadEnd := len(packet)
	if packet[0]&0x20 != 0 {
		if payloadEnd <= header {
			return nil, false
		}
		paddingLength := int(packet[payloadEnd-1])
		if paddingLength == 0 || paddingLength > payloadEnd-header {
			return nil, false
		}
		payloadEnd -= paddingLength
	}
	if payloadEnd <= header {
		return nil, false
	}
	return packet[header:payloadEnd], true
}

func (media *rtpMedia) authorizeRTPSource(
	source *net.UDPAddr,
	expected rtpNegotiationSnapshot,
) bool {
	if source == nil || source.Port < 1 || source.Port > 65535 {
		return false
	}
	media.routeMu.Lock()
	defer media.routeMu.Unlock()
	select {
	case <-media.closed:
		return false
	default:
	}

	media.mu.Lock()
	defer media.mu.Unlock()
	if !media.negotiationMatchesLocked(expected) || !media.remote.IP.Equal(source.IP) {
		return false
	}
	if media.remote.Port == source.Port {
		return true
	}

	if media.routeManager != nil {
		localPort := media.conn.LocalAddr().(*net.UDPAddr).Port
		if localPort < 1 || localPort > 65535 {
			return false
		}
		address := append(net.IP(nil), source.IP...)
		if err := media.acquireRouteReference(address, uint16(localPort), uint16(source.Port)); err != nil {
			return false
		}
		oldRouteIP := append(net.IP(nil), media.routeIP...)
		if oldRouteIP != nil {
			if err := media.releaseRouteReference(oldRouteIP); err != nil {
				// The endpoint remains unchanged unless both acquiring the new TS
				// authorization and retiring the old reference succeed. A failed
				// rollback stays in routeRefs for a later Close retry.
				_ = media.releaseRouteReference(address)
				return false
			}
		}
		media.routeIP = address
	}
	media.remote.Port = source.Port
	media.generation++
	return true
}

func (media *rtpMedia) Close() error {
	media.routeMu.Lock()
	defer media.routeMu.Unlock()
	media.close.Do(func() {
		close(media.closed)
		var errs []error
		if err := media.conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
		media.closeErr = errors.Join(errs...)
	})

	var routeErrs []error
	if media.routeManager != nil {
		ctx, cancel := context.WithTimeout(context.Background(), rtpRouteTimeout)
		defer cancel()
		for index := 0; index < len(media.routeRefs); {
			address := append(net.IP(nil), media.routeRefs[index]...)
			err := media.routeManager.ReleaseMediaRoute(ctx, address)
			if err != nil {
				routeErrs = append(routeErrs, fmt.Errorf("ims: release RTP route %s: %w", address, err))
				index++
				continue
			}
			media.routeRefs = append(media.routeRefs[:index], media.routeRefs[index+1:]...)
		}
	}
	if len(media.routeRefs) == 0 {
		media.routeIP = nil
	}
	return errors.Join(media.closeErr, errors.Join(routeErrs...))
}

func linearToMuLaw(sample int16) byte {
	value := int(sample)
	sign := byte(0)
	if value < 0 {
		sign, value = 0x80, -value
		if value > 32767 {
			value = 32767
		}
	}
	value += 132
	if value > 32635 {
		value = 32635
	}
	exponent := 7
	for mask := 0x4000; exponent > 0 && value&mask == 0; mask >>= 1 {
		exponent--
	}
	mantissa := (value >> (exponent + 3)) & 0x0f
	return ^(sign | byte(exponent<<4) | byte(mantissa))
}

func muLawToLinear(value byte) int16 {
	value = ^value
	magnitude := ((int(value)&0x0f)<<3 + 132) << ((value & 0x70) >> 4)
	magnitude -= 132
	if value&0x80 != 0 {
		return int16(-magnitude)
	}
	return int16(magnitude)
}

func linearToALaw(sample int16) byte {
	value := int(sample)
	mask := byte(0xd5)
	if value < 0 {
		mask, value = 0x55, -value-1
	}
	if value > 32767 {
		value = 32767
	}
	var encoded byte
	if value < 256 {
		encoded = byte(value >> 4)
	} else {
		exponent := 1
		for threshold := 512; exponent < 7 && value >= threshold; threshold <<= 1 {
			exponent++
		}
		encoded = byte(exponent<<4) | byte((value>>(exponent+3))&0x0f)
	}
	return encoded ^ mask
}

func aLawToLinear(value byte) int16 {
	value ^= 0x55
	magnitude := int(value&0x0f)<<4 + 8
	exponent := int((value & 0x70) >> 4)
	if exponent != 0 {
		magnitude = (magnitude + 0x100) << (exponent - 1)
	}
	if value&0x80 == 0 {
		return int16(-magnitude)
	}
	return int16(magnitude)
}
