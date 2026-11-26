package provider

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// keyFetch is the record of one verification's key fetch. The call that verifies
// puts it in its context (withKeyFetch) and reads it after the verification; the
// key set marks it when that call's own fetch fails. A call reads only its own
// record, so no other call's fetch can be blamed on it or hidden from it.
type keyFetch struct{ failed bool }

type keyFetchKey struct{}

// withKeyFetch returns a context that records the key fetch of one verification,
// with the record.
func withKeyFetch(ctx context.Context) (context.Context, *keyFetch) {
	kf := &keyFetch{}
	return context.WithValue(ctx, keyFetchKey{}, kf), kf
}

// jwksKeys holds the signing keys of an adapter built on OIDC. It implements
// go-oidc's KeySet with the adapter's client.
//
// A verification first tries the keys it has, without waiting for anything else.
// Only when none of them verifies the token does it need a fetch, and then it
// joins the fetch in flight or starts one. Concurrent callers share one fetch,
// and a caller that waits for it honours its context. The fetch runs on its own
// goroutine, so a cancelled caller does not cancel the fetch for the others. A
// caller that read the keys before a fetch completed, and finds the keys newer,
// verifies against them without fetching again.
type jwksKeys struct {
	url      string
	client   *http.Client
	mu       sync.Mutex // guards cur, gen and inflight; held only to read or change them
	cur      jwk.Set    // the keys of the last successful fetch; nil before the first
	gen      uint64     // the number of successful fetches
	inflight *keyFetchCall
}

// keyFetchCall is a fetch of the keys shared by the calls that wait for it.
type keyFetchCall struct {
	done chan struct{} // closed when the fetch has finished
	set  jwk.Set       // the keys it read, on success
	err  error         // its failure, if it failed
}

var _ interface {
	VerifySignature(ctx context.Context, jwt string) ([]byte, error)
} = (*jwksKeys)(nil)

// VerifySignature verifies the JWT, whose algorithm the caller has already
// restricted, with the keys it holds, and fetches the keys when none of them
// verifies it. A failed fetch marks the call's keyFetch record.
func (k *jwksKeys) VerifySignature(ctx context.Context, raw string) ([]byte, error) {
	kf, _ := ctx.Value(keyFetchKey{}).(*keyFetch)
	k.mu.Lock()
	cur, gen := k.cur, k.gen
	k.mu.Unlock()
	if cur != nil {
		if p, err := verifyWith(cur, raw); err == nil {
			return p, nil
		}
	}
	keys, call := k.joinOrStart(gen)
	if call == nil {
		// The keys were fetched after this call read them: they are the newest.
		return verifyWith(keys, raw)
	}
	select {
	case <-call.done:
	case <-ctx.Done():
		if kf != nil {
			kf.failed = true
		}
		return nil, fmt.Errorf("provider: the keys could not be fetched: %w", ctx.Err())
	}
	if call.err != nil {
		if kf != nil {
			kf.failed = true
		}
		return nil, fmt.Errorf("provider: the keys could not be fetched: %w", call.err)
	}
	return verifyWith(call.set, raw)
}

// joinOrStart returns the keys a call needs without a fetch when they were fetched
// after gen, else the fetch in flight, starting one when none is.
func (k *jwksKeys) joinOrStart(gen uint64) (jwk.Set, *keyFetchCall) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.gen != gen {
		return k.cur, nil
	}
	if k.inflight != nil {
		return nil, k.inflight
	}
	call := &keyFetchCall{done: make(chan struct{})}
	k.inflight = call
	go k.run(call)
	return nil, call
}

// run fetches the keys for call and publishes the outcome to the callers that wait
// for it. The fetch is bounded by the client's timeout, not by any caller.
func (k *jwksKeys) run(call *keyFetchCall) {
	set, err := k.fetch(context.Background())
	k.mu.Lock()
	if err == nil {
		k.cur = set
		k.gen++
	}
	call.set, call.err = set, err
	k.inflight = nil
	k.mu.Unlock()
	close(call.done)
}

// verifyWith verifies the JWT with the keys of set. Keys that publish no alg are
// used too: the algorithm is inferred from the key, and the caller has already
// restricted the token's algorithm to the configured ones (go-oidc's rule).
func verifyWith(set jwk.Set, raw string) ([]byte, error) {
	p, err := jws.Verify([]byte(raw), jws.WithKeySet(set, jws.WithInferAlgorithmFromKey(true)))
	if err != nil {
		return nil, errors.New("provider: the token is not signed by the published keys")
	}
	return p, nil
}

// fetch reads the key set of the provider once; the client's transport retries
// a failed read.
func (k *jwksKeys) fetch(ctx context.Context) (jwk.Set, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := k.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		return nil, fmt.Errorf("the key endpoint answered %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	return jwk.Parse(body)
}
