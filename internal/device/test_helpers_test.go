package device

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"vocat/internal/modem"
	"vocat/internal/pcsc"
)

type clientStep struct {
	command  string
	response modem.Response
	err      error
}

type promptClientStep struct {
	command      string
	payload      string
	validateBody func(string) error
	response     modem.Response
	err          error
}

type transcriptClient struct {
	mu          sync.Mutex
	steps       []clientStep
	promptSteps []promptClientStep
	urcs        []string
	unexpected  error
	closeCount  int
}

func (client *transcriptClient) ExecutePrompt(
	ctx context.Context,
	command string,
	payload []byte,
) (modem.Response, error) {
	if err := ctx.Err(); err != nil {
		return modem.Response{}, err
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if len(client.promptSteps) == 0 {
		client.unexpected = fmt.Errorf(
			"unexpected prompt command %q with payload %q",
			command,
			payload,
		)
		return modem.Response{}, client.unexpected
	}
	step := client.promptSteps[0]
	client.promptSteps = client.promptSteps[1:]
	if command != step.command {
		client.unexpected = fmt.Errorf(
			"prompt command %q, want %q",
			command,
			step.command,
		)
		return modem.Response{}, client.unexpected
	}
	if step.validateBody != nil {
		if err := step.validateBody(string(payload)); err != nil {
			client.unexpected = err
			return modem.Response{}, err
		}
	} else if string(payload) != step.payload {
		client.unexpected = fmt.Errorf(
			"prompt payload %q, want %q",
			payload,
			step.payload,
		)
		return modem.Response{}, client.unexpected
	}
	response := step.response
	if response.Command == "" {
		response.Command = command
	}
	return response, step.err
}

func (client *transcriptClient) Execute(
	ctx context.Context,
	command string,
) (modem.Response, error) {
	if err := ctx.Err(); err != nil {
		return modem.Response{}, err
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if len(client.steps) == 0 {
		client.unexpected = fmt.Errorf("unexpected command %q", command)
		return modem.Response{}, client.unexpected
	}
	step := client.steps[0]
	client.steps = client.steps[1:]
	if command != step.command {
		client.unexpected = fmt.Errorf("command %q, want %q", command, step.command)
		return modem.Response{}, client.unexpected
	}
	response := step.response
	if response.Command == "" {
		response.Command = command
	}
	return response, step.err
}

func (client *transcriptClient) WaitURC(
	ctx context.Context,
	predicate func(string) bool,
) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	for index, line := range client.urcs {
		if predicate(line) {
			client.urcs = append(client.urcs[:index], client.urcs[index+1:]...)
			return line, nil
		}
	}
	client.unexpected = errors.New("no matching URC in transcript")
	return "", client.unexpected
}

func (client *transcriptClient) Close() error {
	client.mu.Lock()
	client.closeCount++
	client.mu.Unlock()
	return nil
}

func (client *transcriptClient) assertDone(t *testing.T) {
	t.Helper()
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.unexpected != nil {
		t.Fatalf("transcript error: %v", client.unexpected)
	}
	if len(client.steps) != 0 {
		t.Fatalf("%d command transcript steps remain; next is %q", len(client.steps), client.steps[0].command)
	}
	if len(client.promptSteps) != 0 {
		t.Fatalf(
			"%d prompt transcript steps remain; next is %q",
			len(client.promptSteps),
			client.promptSteps[0].command,
		)
	}
}

type staticDiscoverer struct {
	candidates []modem.Candidate
	err        error
}

func (discoverer staticDiscoverer) Discover(
	ctx context.Context,
) ([]modem.Candidate, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result := append([]modem.Candidate(nil), discoverer.candidates...)
	return result, discoverer.err
}

type staticOpener struct {
	mu        sync.Mutex
	client    modem.Client
	err       error
	openCount int
	ports     []modem.Port
}

func (opener *staticOpener) Open(
	ctx context.Context,
	port modem.Port,
) (modem.Client, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	opener.mu.Lock()
	defer opener.mu.Unlock()
	opener.openCount++
	opener.ports = append(opener.ports, port)
	return opener.client, opener.err
}

func newStartedTestManager(
	t *testing.T,
	client modem.Client,
) (*Manager, string) {
	t.Helper()
	const id = "quectel-test-ec20"
	opener := &staticOpener{client: client}
	manager, err := NewManager(Options{
		Discoverer: staticDiscoverer{candidates: []modem.Candidate{{
			ID:           id,
			VendorID:     "2c7c",
			ProductID:    "0125",
			Manufacturer: "Quectel",
			Product:      "EC20",
			ATPort: modem.Port{
				Path:            "/dev/ttyUSB2",
				Name:            "ttyUSB2",
				InterfaceNumber: 0x04,
				Role:            modem.PortRoleAT,
			},
		}}},
		Opener:         opener,
		CardReaders:    pcsc.NewWithBackend(testPCSCBackend{}),
		CommandTimeout: time.Second,
		LongTimeout:    time.Second,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		_ = manager.Stop(context.Background())
	})
	return manager, id
}

func okResponse(lines ...string) modem.Response {
	return modem.Response{Lines: lines, Final: "OK"}
}
