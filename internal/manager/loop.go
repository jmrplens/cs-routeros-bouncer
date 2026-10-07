package manager

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jmrplens/cs-routeros-bouncer/internal/crowdsec"
)

// passKind is what started a reconciliation pass: it decides whether the pass
// waits for a calm router first and what its end logs.
type passKind int

const (
	passFirst    passKind = iota // the first, from the startup decisions
	passPeriodic                 // crowdsec.reconciliation_interval
	passRetry                    // a failed pass's retry, or the one a failed ban owes
	passReboot                   // the router rebooted
)

// waitsForCalm reports whether a pass of kind waits for the router's CPU
// first: the periodic and retry passes do, the first and the reboot passes,
// which must restore what the router lost, do not.
func (k passKind) waitsForCalm() bool {
	return k == passPeriodic || k == passRetry
}

// passRun is a reconciliation pass running beside the decision loop.
type passRun struct {
	kind   passKind
	done   chan error
	cancel context.CancelFunc
}

// decisionLoop is the state of the decision loop: live decisions are applied
// as they arrive, also while a reconciliation pass runs on its own goroutine
// (see livepass.go). One pass runs at a time; a tick, retry or reboot that
// arrives during one owes a single pass after it, as a ticker keeps a single
// tick, and the retry state is only touched here.
type decisionLoop struct {
	m          *Manager
	pass       *passRun
	owed       bool
	owedKind   passKind
	reconcileC <-chan time.Time
	retryC     <-chan time.Time
	initial    []*crowdsec.Decision // the first pass's decisions
	afterFirst func()               // run once the first pass has ended, not on a shutdown
}

// run applies live decisions and runs passes until ctx is done or the stream
// fails, and returns once no pass runs any more.
func (l *decisionLoop) run(ctx context.Context, banCh, deleteCh <-chan *crowdsec.Decision, errCh <-chan error, rebootC <-chan struct{}) error {
	m := l.m
	for {
		select {
		case <-ctx.Done():
			l.stopPass()
			m.logger.Info().Msg("shutting down manager")
			return nil

		case streamErr := <-errCh:
			l.stopPass()
			return fmt.Errorf("CrowdSec stream error: %w", streamErr)

		case d := <-banCh:
			if m.liveBan(d) {
				l.reconcileSoon()
			}

		case d := <-deleteCh:
			m.liveUnban(d)

		case <-l.reconcileC:
			l.request(ctx, passPeriodic)

		case <-rebootC:
			m.logger.Warn().Msg("router rebooted, reconciling the address lists")
			// The router lost every dynamic entry: if this pass fails, its
			// retry starts from the first wait, not from an earlier back-off.
			m.retryDelay = 0
			l.request(ctx, passReboot)

		case <-l.retryC:
			l.retryC = nil
			l.request(ctx, passRetry)

		case err := <-l.passDone():
			l.afterPass(ctx, l.endPass(), err)
		}
	}
}

// passDone is the running pass's result channel, nil when none runs.
func (l *decisionLoop) passDone() <-chan error {
	if l.pass == nil {
		return nil
	}
	return l.pass.done
}

// request runs a pass of kind, or owes one if a pass is running: the owed
// pass is a reboot's if any asked for one, so it does not wait for calm.
func (l *decisionLoop) request(ctx context.Context, kind passKind) {
	if l.pass != nil {
		if !l.owed || kind == passReboot {
			l.owedKind = kind
		}
		l.owed = true
		return
	}
	l.start(ctx, kind)
}

// start runs a pass of kind on its own goroutine, with the journal of live
// decisions open.
func (l *decisionLoop) start(ctx context.Context, kind passKind) {
	m := l.m
	m.beginPass()
	passCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	initial := l.initial
	go func() {
		if kind.waitsForCalm() {
			if err := m.pacing().WaitCalm(passCtx, reconcileCalmWaitMax); err != nil {
				done <- err
				return
			}
		}
		if kind == passFirst {
			done <- m.reconcileAddresses(passCtx, initial)
			return
		}
		done <- m.reconcileActiveDecisions(passCtx)
	}()
	l.pass = &passRun{kind: kind, done: done, cancel: cancel}
}

// endPass forgets the pass that has just reported, and returns its kind.
func (l *decisionLoop) endPass() passKind {
	kind := l.pass.kind
	l.pass.cancel()
	l.pass = nil
	return kind
}

// stopPass ends a running pass and waits for it. Its journal is dropped:
// nothing settles it on the way out.
func (l *decisionLoop) stopPass() {
	if l.pass == nil {
		return
	}
	l.pass.cancel()
	<-l.pass.done
	l.pass = nil
	l.m.dropPassJournal()
	l.m.retryDelay = 0 // as a pass a shutdown ended
}

// afterPass handles the end of a pass of kind: the retry it owes, if it
// failed, settling the live decisions taken during it, and the pass owed.
// While the snapshot fails the wait grows to snapshotRetryMax only.
func (l *decisionLoop) afterPass(ctx context.Context, kind passKind, err error) {
	m := l.m
	if err == nil || ctx.Err() != nil {
		// A pass that succeeded, or that a shutdown ended, owes no retry.
		m.retryDelay = 0
		l.retryC = nil
	}
	if ctx.Err() != nil {
		return // shutting down: the next turn returns
	}
	if err != nil {
		limit := reconcileRetryMax
		if errors.Is(err, errSnapshotFailed) {
			limit = snapshotRetryMax
		}
		l.retryC = m.scheduleReconcileRetry(err, limit)
	}
	if m.settleLive() {
		l.reconcileSoon()
	}
	if kind == passFirst {
		if err != nil {
			m.logger.Warn().Msg("first reconciliation incomplete, processing live decisions")
		} else {
			m.logger.Info().Msg("reconciliation complete, processing live decisions")
		}
		if l.afterFirst != nil {
			l.afterFirst()
		}
	}
	if l.owed {
		l.owed = false
		l.start(ctx, l.owedKind)
	}
}

// reconcileSoon owes the reconcile a failed live ban owes, unless a retry
// already runs sooner. The back-off of a failed reconcile stays.
func (l *decisionLoop) reconcileSoon() {
	if l.retryC == nil || time.Until(l.m.retryAt) > reconcileRetryInterval {
		l.retryC = l.m.reconcileSoon()
	}
}
