package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// runLoadtest floods a running server with messages between TWO already
// existing accounts to measure message-ingest throughput. It deliberately
// creates NO accounts and NO devices (those are hard to remove): a send only
// inserts a transient `messages` row (drained here) plus a transient
// `used_nonces` row (auto-expires server-side). Run it against a local/dev
// server, never production.
//
// The payload is an opaque dummy blob -- the server never inspects a message
// payload, so this measures the pure send pipeline (auth, queue-cap check, row
// insert, SQLite single-writer) rather than the ratchet. The recipient side
// just drains (list + delete) without decrypting.
func runLoadtest(args []string) error {
	fs := flag.NewFlagSet("loadtest", flag.ExitOnError)
	dataDir := fs.String("datadir", "./devclient-data", "sender state directory")
	to := fs.String("to", "", "peer account id to flood (an existing account)")
	count := fs.Int("count", 1000, "total messages to send")
	concurrency := fs.Int("concurrency", 8, "number of parallel senders")
	drainDataDir := fs.String("drain-datadir", "", "receiver state directory; if set, drains the recipient queue in parallel so it never hits the per-device cap")
	payloadBytes := fs.Int("payload-bytes", 256, "size of the dummy payload in bytes")
	verboseFlag := fs.Bool("verbose", false, "log every request to the server")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *to == "" {
		return fmt.Errorf("loadtest: -to is required")
	}
	if *count <= 0 || *concurrency <= 0 {
		return fmt.Errorf("loadtest: -count and -concurrency must be > 0")
	}
	verbose = *verboseFlag

	senderState, err := LoadState(statePath(*dataDir))
	if err != nil {
		return err
	}
	peerAccountID, peerDeviceID, _, err := resolvePeerDevice(senderState.Server, *to)
	if err != nil {
		return fmt.Errorf("resolving peer: %w", err)
	}

	var drainState *State
	if *drainDataDir != "" {
		drainState, err = LoadState(statePath(*drainDataDir))
		if err != nil {
			return fmt.Errorf("loading drain state: %w", err)
		}
	}

	payload := dummyPayload(*payloadBytes)

	fmt.Printf("Load test: %d messages → %s (device %s) on %s, concurrency %d\n",
		*count, shortID(peerAccountID), peerDeviceID, senderState.Server, *concurrency)
	if drainState == nil {
		fmt.Println("WARNING: no -drain-datadir; the recipient queue is not being drained and will hit the per-device cap (429) once full.")
	}

	// Drainer: keep the recipient's queue empty so the send side measures
	// server ingest, not queue-cap backpressure.
	doneSending := make(chan struct{})
	var drained int64
	var drainWG sync.WaitGroup
	if drainState != nil {
		drainWG.Add(1)
		go func() {
			defer drainWG.Done()
			drainQueue(drainState, doneSending, *concurrency, &drained)
		}()
	}

	// Senders.
	var (
		sent         int64
		mu           sync.Mutex
		latencies    []time.Duration
		statusCounts = map[int]int{}
		transportErr int
	)
	start := time.Now()
	var wg sync.WaitGroup
	for w := 0; w < *concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if atomic.AddInt64(&sent, 1) > int64(*count) {
					return
				}
				msgID, err := randomMessageID()
				if err != nil {
					mu.Lock()
					transportErr++
					mu.Unlock()
					continue
				}
				body, err := json.Marshal(sendMessageRequest{MessageID: msgID, RecipientDeviceID: peerDeviceID, Payload: payload})
				if err != nil {
					mu.Lock()
					transportErr++
					mu.Unlock()
					continue
				}
				t0 := time.Now()
				resp, err := signedRequest(senderState, http.MethodPost, "/v1/messages", body)
				d := time.Since(t0)
				if err != nil {
					mu.Lock()
					transportErr++
					mu.Unlock()
					continue
				}
				status := resp.StatusCode
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				mu.Lock()
				latencies = append(latencies, d)
				statusCounts[status]++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)
	close(doneSending)
	drainWG.Wait()

	report(elapsed, *count, statusCounts, transportErr, latencies, drainState != nil, drained)
	return nil
}

// dummyPayload builds an opaque JSON blob of roughly n bytes. The server never
// parses a payload, so its contents are irrelevant beyond being valid JSON.
func dummyPayload(n int) json.RawMessage {
	if n < 0 {
		n = 0
	}
	b, _ := json.Marshal(map[string]string{"loadtest": "1", "pad": strings.Repeat("x", n)})
	return json.RawMessage(b)
}

// drainQueue lists the recipient's pending messages and deletes them via a pool
// of deleters, until sending is done and the queue reads empty. A seen-set
// ensures each message id is enqueued for deletion exactly once even though a
// message stays in the listed queue until its DELETE lands -- without it the
// lister would re-enqueue the same ids every poll, inflating the count and
// piling redundant DELETEs onto the same single SQLite writer the senders are
// contending for.
func drainQueue(state *State, doneSending <-chan struct{}, deleters int, drained *int64) {
	idCh := make(chan string, 4096)
	var delWG sync.WaitGroup
	for i := 0; i < deleters; i++ {
		delWG.Add(1)
		go func() {
			defer delWG.Done()
			for id := range idCh {
				ackMessage(state, id) // best-effort DELETE
				atomic.AddInt64(drained, 1)
			}
		}()
	}

	seen := make(map[string]bool)
	sendingDone := false
	for {
		msgs, err := listPending(state)
		fresh := 0
		if err == nil {
			for _, m := range msgs {
				if seen[m.MessageID] {
					continue
				}
				seen[m.MessageID] = true
				fresh++
				idCh <- m.MessageID
			}
		}
		select {
		case <-doneSending:
			sendingDone = true
		default:
		}
		if sendingDone && err == nil && len(msgs) == 0 {
			close(idCh)
			delWG.Wait()
			return
		}
		if err != nil || fresh == 0 {
			time.Sleep(30 * time.Millisecond)
		}
	}
}

// listPending fetches the caller device's pending message queue.
func listPending(state *State) ([]messageResponse, error) {
	resp, err := signedRequest(state, http.MethodGet, "/v1/messages", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("list failed: %s", resp.Status)
	}
	var msgs []messageResponse
	if err := json.NewDecoder(resp.Body).Decode(&msgs); err != nil {
		return nil, err
	}
	return msgs, nil
}

func report(elapsed time.Duration, count int, statusCounts map[int]int, transportErr int, latencies []time.Duration, drainOn bool, drained int64) {
	ok := statusCounts[http.StatusAccepted]
	total := 0
	for _, c := range statusCounts {
		total += c
	}
	total += transportErr

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })

	fmt.Println()
	fmt.Println("Load test complete.")
	fmt.Printf("  duration:    %s\n", elapsed.Round(time.Millisecond))
	fmt.Printf("  attempted:   %d\n", count)
	fmt.Printf("  sent ok:     %d (202 Accepted)\n", ok)
	fmt.Printf("  errors:      %d\n", total-ok)
	fmt.Printf("    429 recipient_queue_full: %d\n", statusCounts[http.StatusTooManyRequests])
	fmt.Printf("    409 message_exists:       %d\n", statusCounts[http.StatusConflict])
	fmt.Printf("    401 unauthorized:         %d\n", statusCounts[http.StatusUnauthorized])
	fmt.Printf("    413 payload_too_large:    %d\n", statusCounts[http.StatusRequestEntityTooLarge])
	fmt.Printf("    transport errors:         %d\n", transportErr)
	for status, c := range statusCounts {
		switch status {
		case http.StatusAccepted, http.StatusTooManyRequests, http.StatusConflict, http.StatusUnauthorized, http.StatusRequestEntityTooLarge:
		default:
			fmt.Printf("    HTTP %d:                   %d\n", status, c)
		}
	}
	if ok > 0 && elapsed > 0 {
		fmt.Printf("  throughput:  %.0f msgs/s (accepted)\n", float64(ok)/elapsed.Seconds())
	}
	if len(latencies) > 0 {
		fmt.Printf("  latency:     p50 %s  p95 %s  p99 %s  max %s\n",
			percentile(latencies, 0.50).Round(time.Millisecond),
			percentile(latencies, 0.95).Round(time.Millisecond),
			percentile(latencies, 0.99).Round(time.Millisecond),
			latencies[len(latencies)-1].Round(time.Millisecond))
	}
	if drainOn {
		fmt.Printf("  drained:     %d messages from the recipient queue\n", drained)
	}
}

func percentile(sorted []time.Duration, q float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted)-1) * q)
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}
