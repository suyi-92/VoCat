package ike

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"vocat/internal/vowifi"
)

type fakeDynamicRouteChild struct {
	adds     []string
	removes  []string
	closed   bool
	onAdd    func()
	onRemove func()
}

func (child *fakeDynamicRouteChild) AddRoute(_ context.Context, destination net.IP) error {
	if child.onAdd != nil {
		child.onAdd()
	}
	child.adds = append(child.adds, destination.String())
	return nil
}

func (child *fakeDynamicRouteChild) RemoveRoute(_ context.Context, destination net.IP) error {
	if child.onRemove != nil {
		child.onRemove()
	}
	child.removes = append(child.removes, destination.String())
	return nil
}

func (child *fakeDynamicRouteChild) Close(context.Context) error {
	child.closed = true
	return nil
}

func mediaRouteTestSession(child *fakeDynamicRouteChild) *Session {
	config := ChildSAConfig{
		InnerLocalIPv4: net.IPv4(10, 132, 116, 34),
		InitiatorSelectors: []trafficSelector{{
			IPProtocol: mediaRouteUDPProtocol,
			StartPort:  4000,
			EndPort:    4999,
			StartIP:    net.IPv4(10, 132, 116, 34),
			EndIP:      net.IPv4(10, 132, 116, 34),
		}},
		ResponderSelectors: []trafficSelector{{
			IPProtocol: mediaRouteUDPProtocol,
			StartPort:  10000,
			EndPort:    20000,
			StartIP:    net.IPv4(10, 0, 0, 0),
			EndIP:      net.IPv4(10, 255, 255, 255),
		}},
	}
	return &Session{
		evidence:    vowifi.TunnelEvidence{Established: true, DataplaneMode: "userspace"},
		child:       child,
		routePolicy: newMediaRoutePolicy(config),
		routeRefs:   make(map[string]int),
	}
}

func TestSessionMediaRoutesAreValidatedAndReferenceCounted(t *testing.T) {
	child := &fakeDynamicRouteChild{}
	session := mediaRouteTestSession(child)
	destination := net.IPv4(10, 20, 30, 40)

	for range 2 {
		if err := session.AcquireMediaRoute(
			context.Background(),
			destination,
			4500,
			16000,
		); err != nil {
			t.Fatal(err)
		}
	}
	if len(child.adds) != 1 || child.adds[0] != "10.20.30.40" {
		t.Fatalf("route adds = %#v, want one canonical destination", child.adds)
	}
	if err := session.ReleaseMediaRoute(context.Background(), destination); err != nil {
		t.Fatal(err)
	}
	if len(child.removes) != 0 {
		t.Fatalf("route removed with an outstanding reference: %#v", child.removes)
	}
	if err := session.ReleaseMediaRoute(context.Background(), destination); err != nil {
		t.Fatal(err)
	}
	if err := session.ReleaseMediaRoute(context.Background(), destination); err != nil {
		t.Fatal(err)
	}
	if len(child.removes) != 1 || child.removes[0] != "10.20.30.40" {
		t.Fatalf("route removes = %#v, want one canonical destination", child.removes)
	}

	for _, test := range []struct {
		name       string
		remote     net.IP
		localPort  uint16
		remotePort uint16
	}{
		{name: "remote address", remote: net.IPv4(203, 0, 113, 1), localPort: 4500, remotePort: 16000},
		{name: "local port", remote: destination, localPort: 6000, remotePort: 16000},
		{name: "remote port", remote: destination, localPort: 4500, remotePort: 9000},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := session.AcquireMediaRoute(
				context.Background(),
				test.remote,
				test.localPort,
				test.remotePort,
			); err == nil {
				t.Fatal("endpoint outside negotiated selectors was accepted")
			}
		})
	}
	if len(child.adds) != 1 {
		t.Fatalf("rejected endpoints changed platform routes: %#v", child.adds)
	}
}

func TestSessionMediaRoutePlatformCallsDoNotHoldSessionMutex(t *testing.T) {
	child := &fakeDynamicRouteChild{}
	session := mediaRouteTestSession(child)
	child.onAdd = func() {
		_ = session.Evidence()
	}
	child.onRemove = func() {
		_ = session.Network()
	}
	done := make(chan error, 1)
	go func() {
		destination := net.IPv4(10, 20, 30, 40)
		if err := session.AcquireMediaRoute(context.Background(), destination, 4500, 16000); err != nil {
			done <- err
			return
		}
		done <- session.ReleaseMediaRoute(context.Background(), destination)
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("platform route call deadlocked on Session.mu")
	}
}

type blockingDynamicRouteChild struct {
	addStarted chan struct{}
	allowAdd   chan struct{}
	closed     chan struct{}
}

func (child *blockingDynamicRouteChild) AddRoute(context.Context, net.IP) error {
	close(child.addStarted)
	<-child.allowAdd
	return nil
}

func (*blockingDynamicRouteChild) RemoveRoute(context.Context, net.IP) error { return nil }

func (child *blockingDynamicRouteChild) Close(context.Context) error {
	close(child.closed)
	return nil
}

func TestSessionCloseWaitsForInFlightMediaRouteOperation(t *testing.T) {
	child := &blockingDynamicRouteChild{
		addStarted: make(chan struct{}),
		allowAdd:   make(chan struct{}),
		closed:     make(chan struct{}),
	}
	session := mediaRouteTestSession(nil)
	session.child = child
	acquired := make(chan error, 1)
	go func() {
		acquired <- session.AcquireMediaRoute(
			context.Background(),
			net.IPv4(10, 20, 30, 40),
			4500,
			16000,
		)
	}()
	select {
	case <-child.addStarted:
	case <-time.After(time.Second):
		t.Fatal("platform route operation did not start")
	}
	closed := make(chan error, 1)
	go func() { closed <- session.Close(context.Background()) }()
	select {
	case <-child.closed:
		t.Fatal("CHILD_SA closed while a route operation still used it")
	case <-time.After(50 * time.Millisecond):
	}
	close(child.allowAdd)
	if err := <-acquired; err != nil {
		t.Fatal(err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	select {
	case <-child.closed:
	default:
		t.Fatal("CHILD_SA did not close after the route operation completed")
	}
}

var _ ChildSADynamicRouteManager = (*fakeDynamicRouteChild)(nil)
var _ ChildSADynamicRouteManager = (*blockingDynamicRouteChild)(nil)

type retryCloseChild struct {
	calls int
	err   error
}

func (child *retryCloseChild) Close(context.Context) error {
	child.calls++
	if child.calls == 1 {
		return child.err
	}
	return nil
}

func TestSessionCloseRetriesFailedChildCleanup(t *testing.T) {
	cleanupErr := errors.New("platform cleanup failed")
	child := &retryCloseChild{err: cleanupErr}
	session := &Session{
		evidence:  vowifi.TunnelEvidence{Established: true},
		child:     child,
		routeRefs: map[string]int{"10.20.30.40": 1},
	}
	if err := session.Close(context.Background()); !errors.Is(err, cleanupErr) {
		t.Fatalf("first Close() error = %v, want %v", err, cleanupErr)
	}
	session.mu.Lock()
	closed := session.closed
	retained := session.child == child
	established := session.evidence.Established
	session.mu.Unlock()
	if !closed || !retained || established {
		t.Fatalf("failed child cleanup was not retained: closed=%v retained=%v established=%v", closed, retained, established)
	}
	if err := session.Close(context.Background()); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if err := session.Close(context.Background()); err != nil {
		t.Fatalf("third Close() error = %v", err)
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.child != nil || session.routeRefs != nil || child.calls != 2 {
		t.Fatalf("successful retry did not finalize child: child=%T refs=%#v calls=%d", session.child, session.routeRefs, child.calls)
	}
}

var _ ChildSAHandle = (*retryCloseChild)(nil)
