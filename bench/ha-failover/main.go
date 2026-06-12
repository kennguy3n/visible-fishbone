// Command ha-failover is a reproducible high-availability validation
// harness for the Postgres advisory-lock leader election in
// internal/service/leader. It measures the recovery time objective
// (RTO) of the control plane's leader-gated background loops under a
// hard leader crash.
//
// It is deliberately MULTI-PROCESS: each "replica" is a separate OS
// process running a real leader.LeaderElector against a shared
// Postgres database (the only coordination point that works across
// processes, and the real one used in production). The orchestrator
// launches N replica processes, waits for one to win the advisory
// lock, SIGKILLs that leader process (an ungraceful crash — no
// graceful Unlock, exactly like a pod OOM/segfault), and measures the
// wall-clock time until a surviving replica acquires leadership. That
// interval is the failover RTO: it includes Postgres detecting the
// dead backend and releasing the session-level advisory lock, plus a
// follower's next election poll acquiring it.
//
// HONESTY: this is a single-host, multi-process test. It exercises
// the real election code path and real Postgres advisory-lock
// session semantics, but it is NOT a true multi-node cluster: there
// is no inter-node network, no separate Postgres primary/standby, and
// the crash is a local SIGKILL rather than a host/network partition.
// See docs/ha-failover.md for the full HA model and caveats.
//
// Usage (orchestrator, the default role):
//
//	export DATABASE_URL='postgres://ha:ha@127.0.0.1:5432/ha_failover?sslmode=disable'
//	go run ./bench/ha-failover -replicas=3 -trials=5 -interval=250ms
//
// The -role=replica mode is an internal entrypoint the orchestrator
// re-execs; it is not meant to be invoked directly.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kennguy3n/visible-fishbone/internal/service/leader"
)

func main() {
	role := flag.String("role", "orchestrator", "orchestrator | replica")
	dbURL := flag.String("db", os.Getenv("DATABASE_URL"), "Postgres connection URL (or set DATABASE_URL)")
	replicas := flag.Int("replicas", 3, "number of replica processes")
	trials := flag.Int("trials", 5, "number of kill/failover trials to measure")
	interval := flag.Duration("interval", 250*time.Millisecond, "election check interval per replica")
	lockID := flag.Int64("lockid", 0, "advisory lock id (0 = derive a fresh one); replicas inherit it")
	flag.Parse()

	if *dbURL == "" {
		fmt.Fprintln(os.Stderr, "ha-failover: -db or DATABASE_URL is required")
		os.Exit(2)
	}

	if *role == "replica" {
		if err := runReplica(*dbURL, *lockID, *interval); err != nil {
			fmt.Fprintf(os.Stderr, "replica: %v\n", err)
			os.Exit(1)
		}
		return
	}

	id := *lockID
	if id == 0 {
		// A fresh, run-unique lock id so concurrent runs (or stale
		// locks from a previous crash) never collide.
		id = leader.LockIDForName(fmt.Sprintf("ha-failover-%d-%d", os.Getpid(), rand.Int63())) //nolint:gosec // non-crypto run-unique lock id
	}
	if err := orchestrate(*dbURL, id, *replicas, *trials, *interval); err != nil {
		fmt.Fprintf(os.Stderr, "orchestrator: %v\n", err)
		os.Exit(1)
	}
}

// ---- replica -------------------------------------------------------

// replicaEvent is the line protocol a replica prints on stdout so the
// orchestrator can observe leadership transitions.
type replicaEvent struct {
	Event string `json:"event"` // "acquired" | "lost" | "ready"
	PID   int    `json:"pid"`
	Epoch uint64 `json:"epoch,omitempty"`
}

func runReplica(dbURL string, lockID int64, interval time.Duration) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer pool.Close()

	e := leader.New(
		leader.NewPgSessionOpener(pool),
		leader.WithLockID(lockID),
		leader.WithCheckInterval(interval),
		leader.WithIdentity(fmt.Sprintf("replica-%d", os.Getpid())),
	)

	go e.Run(ctx)

	enc := json.NewEncoder(os.Stdout)
	emit := func(ev string, epoch uint64) { _ = enc.Encode(replicaEvent{Event: ev, PID: os.Getpid(), Epoch: epoch}) }
	emit("ready", 0)

	// Poll leadership on a fine cadence and report rising/falling
	// edges. This poll only OBSERVES state the elector already
	// maintains; it does not influence election timing.
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	was := false
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			now := e.IsLeader()
			if now && !was {
				var epoch uint64
				if tok, ok := e.FencingToken(); ok {
					epoch = tok.Epoch
				}
				emit("acquired", epoch)
			} else if !now && was {
				emit("lost", 0)
			}
			was = now
		}
	}
}

// ---- orchestrator --------------------------------------------------

// observed pairs a replica event with the orchestrator's wall-clock
// timestamp at the moment it read the event, so all timing is on a
// single clock.
type observed struct {
	ev replicaEvent
	at time.Time
}

type replicaProc struct {
	cmd  *exec.Cmd
	pid  int
	slot int
}

func orchestrate(dbURL string, lockID int64, n, trials int, interval time.Duration) error {
	fmt.Printf("ha-failover orchestrator: replicas=%d trials=%d interval=%s lock_id=%d\n", n, trials, interval, lockID)
	fmt.Printf("backend: %s\n\n", redactURL(dbURL))

	// All replica processes are children of this context, so they are
	// torn down when orchestrate returns for any reason.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	events := make(chan observed, 256)
	procs := make([]*replicaProc, n)

	// settle is how long we let a freshly launched replica run before
	// it is eligible to be measured. It must exceed one check interval
	// so the replica's boot-time immediate election has already
	// happened (and failed, since the lock is held) and it is in
	// steady-state periodic polling. Without this, a replica launched
	// into the brief lock-free window right after a kill could acquire
	// via its *startup* election, which would measure process boot
	// time, not an already-running follower's failover.
	settle := 2*interval + 250*time.Millisecond

	launch := func(slot int) (*replicaProc, error) {
		p, err := startReplica(ctx, dbURL, lockID, interval, events)
		if err != nil {
			return nil, err
		}
		p.slot = slot
		procs[slot] = p
		return p, nil
	}

	for slot := 0; slot < n; slot++ {
		if _, err := launch(slot); err != nil {
			return fmt.Errorf("launch replica %d: %w", slot, err)
		}
	}
	defer func() {
		for _, p := range procs {
			if p != nil && p.cmd.Process != nil {
				_ = p.cmd.Process.Kill()
			}
		}
	}()

	// Track current leader pid as transitions stream in.
	leaderPID := 0
	currentLeader := func() int { return leaderPID }
	apply := func(o observed) {
		switch o.ev.Event {
		case "acquired":
			leaderPID = o.ev.PID
		case "lost":
			if leaderPID == o.ev.PID {
				leaderPID = 0
			}
		}
	}

	waitForLeader := func(timeout time.Duration) (int, error) {
		deadline := time.After(timeout)
		for {
			if currentLeader() != 0 {
				return currentLeader(), nil
			}
			select {
			case o := <-events:
				apply(o)
			case <-deadline:
				return 0, fmt.Errorf("timed out waiting for a leader to be elected")
			}
		}
	}

	// waitForReady blocks until the replica with the given pid reports
	// that its elector is running, so we never start a measurement
	// timer before a relaunched replica is actually up.
	waitForReady := func(pid int, timeout time.Duration) error {
		deadline := time.After(timeout)
		for {
			select {
			case o := <-events:
				apply(o)
				if o.ev.Event == "ready" && o.ev.PID == pid {
					return nil
				}
			case <-deadline:
				return fmt.Errorf("timed out waiting for replica pid %d to report ready", pid)
			}
		}
	}

	// pumpUntil keeps draining and applying events for d so the
	// leader-tracking state stays current (and the bounded events
	// channel never backs up) while the cluster stabilizes.
	pumpUntil := func(d time.Duration) {
		deadline := time.After(d)
		for {
			select {
			case o := <-events:
				apply(o)
			case <-deadline:
				return
			}
		}
	}

	pid, err := waitForLeader(30 * time.Second)
	if err != nil {
		return err
	}
	// Let every replica reach steady state before the first measured
	// trial so trial 1 is also a genuine already-running-follower
	// failover, not a race with boot-time elections.
	pumpUntil(settle)
	fmt.Printf("initial leader elected: pid=%d (cluster settled)\n\n", pid)

	// jitter is a uniform random delay in [0, interval). A real crash
	// happens at an arbitrary instant relative to each follower's
	// election ticker; sampling a random phase before every kill makes
	// the measured RTO a fair draw from the true failover distribution
	// instead of an artifact of synchronized ticker phases.
	jitter := func() time.Duration {
		if interval <= 0 {
			return 0
		}
		return time.Duration(rand.Int63n(int64(interval))) //nolint:gosec // non-crypto crash-phase sampling
	}

	var rtos []time.Duration
	for trial := 1; trial <= trials; trial++ {
		oldPID := currentLeader()
		p := findProc(procs, oldPID)
		if p == nil {
			return fmt.Errorf("trial %d: no process for leader pid %d", trial, oldPID)
		}

		// Desynchronize the kill from the followers' ticker phases.
		pumpUntil(jitter())

		// Hard crash: SIGKILL, no graceful relinquish. All surviving
		// replicas are already running and have been polling for at
		// least one full interval, so whichever takes over does so via
		// its periodic election — a true failover.
		killAt := time.Now()
		if err := p.cmd.Process.Kill(); err != nil {
			return fmt.Errorf("trial %d: kill leader: %w", trial, err)
		}
		leaderPID = 0

		// Measure until a *different*, already-running replica acquires
		// leadership after the kill instant.
		newPID, at, err := waitForNewLeader(events, oldPID, killAt, apply, 60*time.Second)
		if err != nil {
			return fmt.Errorf("trial %d: %w", trial, err)
		}
		rto := at.Sub(killAt)
		rtos = append(rtos, rto)
		fmt.Printf("trial %d: leader pid=%d killed -> pid=%d took over | RTO=%s\n", trial, oldPID, newPID, rto.Round(time.Millisecond))

		// Re-launch the crashed replica so N stays constant, then wait
		// for it to be ready and let the cluster settle so it is a
		// steady-state follower (not booting) before the next kill.
		_ = p.cmd.Wait()
		np, err := launch(p.slot)
		if err != nil {
			return fmt.Errorf("trial %d: relaunch replica: %w", trial, err)
		}
		if err := waitForReady(np.pid, 15*time.Second); err != nil {
			return fmt.Errorf("trial %d: %w", trial, err)
		}
		pumpUntil(settle)
		if _, err := waitForLeader(30 * time.Second); err != nil {
			return err
		}
	}

	printSummary(rtos, n, interval)
	return nil
}

func waitForNewLeader(events chan observed, oldPID int, killAt time.Time, apply func(observed), timeout time.Duration) (int, time.Time, error) {
	deadline := time.After(timeout)
	for {
		select {
		case o := <-events:
			apply(o)
			// Only an acquisition by a *different* replica observed
			// *after* the kill counts as the failover.
			if o.ev.Event == "acquired" && o.ev.PID != oldPID && !o.at.Before(killAt) {
				return o.ev.PID, o.at, nil
			}
		case <-deadline:
			return 0, time.Time{}, fmt.Errorf("timed out waiting for failover")
		}
	}
}

func findProc(procs []*replicaProc, pid int) *replicaProc {
	for _, p := range procs {
		if p != nil && p.pid == pid {
			return p
		}
	}
	return nil
}

func startReplica(ctx context.Context, dbURL string, lockID int64, interval time.Duration, events chan<- observed) (*replicaProc, error) {
	//nolint:gosec // G204: re-execs our own binary (os.Args[0]) with controlled flags; local benchmarking tool, not a server.
	cmd := exec.CommandContext(ctx, os.Args[0],
		"-role=replica",
		"-db="+dbURL,
		fmt.Sprintf("-lockid=%d", lockID),
		"-interval="+interval.String(),
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	p := &replicaProc{cmd: cmd, pid: cmd.Process.Pid}

	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			var ev replicaEvent
			if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
				continue
			}
			// Stamp the observation instant when the line arrives, then
			// deliver with a blocking, ctx-aware send. A measurement
			// event must never be silently dropped (that would corrupt
			// an RTO sample), so we do NOT use a non-blocking send; the
			// orchestrator drains continuously, and the ctx.Done() arm
			// guarantees this goroutine exits instead of leaking once
			// the run ends.
			o := observed{ev: ev, at: time.Now()}
			select {
			case events <- o:
			case <-ctx.Done():
				return
			}
		}
		// stdout closed (process exited); the orchestrator's reads
		// unblock via its own timeouts / ctx.
	}()
	return p, nil
}

func printSummary(rtos []time.Duration, replicas int, interval time.Duration) {
	if len(rtos) == 0 {
		fmt.Println("\nno RTO samples collected")
		return
	}
	sorted := append([]time.Duration(nil), rtos...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	var sum time.Duration
	for _, d := range rtos {
		sum += d
	}
	mean := sum / time.Duration(len(rtos))
	median := sorted[len(sorted)/2]

	fmt.Printf("\n==== RTO summary (n=%d, replicas=%d, check_interval=%s) ====\n", len(rtos), replicas, interval)
	fmt.Printf("min    = %s\n", sorted[0].Round(time.Millisecond))
	fmt.Printf("median = %s\n", median.Round(time.Millisecond))
	fmt.Printf("mean   = %s\n", mean.Round(time.Millisecond))
	fmt.Printf("max    = %s\n", sorted[len(sorted)-1].Round(time.Millisecond))
	fmt.Println("note: RTO scales with -interval; production uses leader.DefaultCheckInterval (30s).")
}

func redactURL(u string) string {
	// Best-effort: hide the password segment for log hygiene.
	at := -1
	colon := -1
	for i := 0; i < len(u); i++ {
		if u[i] == '@' {
			at = i
			break
		}
		if u[i] == ':' && colon == -1 && i > 0 {
			// skip scheme colon
			if i+2 < len(u) && u[i+1] == '/' && u[i+2] == '/' {
				continue
			}
			colon = i
		}
	}
	if at > 0 && colon > 0 && colon < at {
		return u[:colon+1] + "***" + u[at:]
	}
	return u
}
