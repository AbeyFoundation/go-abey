// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Package downloader contains the manual full chain synchronisation.
package downloader

import (
	"errors"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	abeychain "github.com/AbeyFoundation/go-abey"
	"github.com/AbeyFoundation/go-abey/core/rawdb"
	"github.com/AbeyFoundation/go-abey/params"

	"github.com/AbeyFoundation/go-abey/abey/fastdownloader"
	abey "github.com/AbeyFoundation/go-abey/abey/types"
	"github.com/AbeyFoundation/go-abey/abeydb"
	"github.com/AbeyFoundation/go-abey/common"
	"github.com/AbeyFoundation/go-abey/core/types"
	"github.com/AbeyFoundation/go-abey/event"
	"github.com/AbeyFoundation/go-abey/log"
	"github.com/AbeyFoundation/go-abey/metrics"
	//"github.com/AbeyFoundation/go-abey/trie"
)

var (
	MaxHashFetch       = 512 // Amount of hashes to be fetched per retrieval request
	MaxBlockFetch      = 128 // Amount of blocks to be fetched per retrieval request
	MaxHeaderFetch     = 192 // Amount of block headers to be fetched per retrieval request
	MaxFastHeaderFetch = 600 // Amount of fast block headers to be fetched per retrieval request
	MaxSkeletonSize    = 128 // Number of header fetches to need for a skeleton assembly
	MaxBodyFetch       = 128 // Amount of block bodies to be fetched per retrieval request
	MaxReceiptFetch    = 256 // Amount of transaction receipts to allow fetching per request
	MaxStateFetch      = 384 // Amount of node state values to allow fetching per request

	MaxForkAncestry  = 3 * params.EpochDuration // Maximum chain reorganisation
	rttMaxEstimate   = 20 * time.Second         // Maximum round-trip time to target for download requests
	rttMinConfidence = 0.1                      // Worse confidence factor in our estimated RTT value
	ttlScaling       = 3                        // Constant scaling factor for RTT -> TTL conversion
	ttlLimit         = time.Minute              // Maximum TTL allowance to prevent reaching crazy timeouts

	qosConfidenceCap = 10   // Number of peers above which not to modify RTT confidence
	qosTuningImpact  = 0.25 // Impact that a new tuning target has on the previous value

	maxQueuedHeaders  = 32 * 1024 // [eth/62] Maximum number of headers to queue for import (DOS protection)
	maxHeadersProcess = 2048      // Number of header download results to import at once into the chain
	maxResultsProcess = 2048      // Number of content download results to import at once into the chain

	reorgProtThreshold   = 48 // Threshold number of recent blocks to disable mini reorg protection
	reorgProtHeaderDelay = 2  // Number of headers to delay delivering to cover mini reorgs

	fsHeaderSafetyNet = 2048             // Number of headers to discard in case a chain violation is detected
	fsHeaderContCheck = 15 * time.Second // Time interval to check for header continuations during state download

	maxSyncSnailHeight = new(big.Int).Sub(params.SnailRewardInterval, common.Big1).Uint64()
)

var (
	errBusy                    = errors.New("snail busy")
	errUnknownPeer             = errors.New("snail peer is unknown or unhealthy")
	errBadPeer                 = errors.New("snail action from bad peer ignored")
	errStallingPeer            = errors.New("snail peer is stalling")
	errUnsyncedPeer            = errors.New("snail unsynced peer")
	errNoPeers                 = errors.New("snail no peers to keep download active")
	errTimeout                 = errors.New("snail timeout")
	errEmptyHeaderSet          = errors.New("snail empty header set by peer")
	errPeersUnavailable        = errors.New("snail no peers available or all tried for download")
	errInvalidAncestor         = errors.New("snail retrieved ancestor is invalid")
	errInvalidChain            = errors.New("snail retrieved hash chain is invalid")
	errInvalidBlock            = errors.New("snail retrieved block is invalid")
	errInvalidBody             = errors.New("snail retrieved block body is invalid")
	errInvalidReceipt          = errors.New("snail retrieved receipt is invalid")
	errCancelBlockFetch        = errors.New("snail block download canceled (requested)")
	errCancelHeaderFetch       = errors.New("snail block header download canceled (requested)")
	errCancelBodyFetch         = errors.New("snail block body download canceled (requested)")
	errCancelReceiptFetch      = errors.New("snail receipt download canceled (requested)")
	errCancelStateFetch        = errors.New("state data download canceled (requested)")
	errCancelHeaderProcessing  = errors.New("snail header processing canceled (requested)")
	errCancelContentProcessing = errors.New("snail content processing canceled (requested)")
	errNoSyncActive            = errors.New("snail no sync active")
	errTooOld                  = errors.New("snail peer doesn't speak recent enough protocol version (need version >= 62)")
	errFruits                  = errors.New("snail fruits err")
)

type Downloader struct {
	mode SyncMode       // Synchronisation mode defining the strategy used (per sync cycle)
	mux  *event.TypeMux // Event multiplexer to announce sync operation events

	checkpoint uint64        // Checkpoint block number to enforce head against (e.g. fast sync
	genesis    uint64        // Genesis block number to limit sync to (e.g. light client CHT)
	queue      *queue        // Scheduler for selecting the hashes to download
	peers      *abey.PeerSet // Set of active peers from which download can proceed

	stateDB abeydb.Database
	//stateBloom *trie.SyncBloom // Bloom filter for fast trie node existence checks

	rttEstimate   uint64 // Round trip time to target for download requests
	rttConfidence uint64 // Confidence in the estimated RTT (unit: millionths to allow atomic ops)

	// Statistics
	syncStatsChainOrigin uint64       // Origin block number where syncing started at
	syncStatsChainHeight uint64       // Highest block number known when syncing started
	syncStatsLock        sync.RWMutex // Lock protecting the sync stats fields
	syncStatsState       stateSyncStats

	lightchain LightChain
	blockchain BlockChain

	// Callbacks
	dropPeer abey.PeerDropFn // Drops a peer for misbehaving

	// Status
	synchroniseMock func(id string, hash common.Hash) error // Replacement for synchronise during testing
	synchronising   int32
	notified        int32
	committed       int32
	ancientLimit    uint64 // The maximum block number which can be regarded as ancient data.

	// Channels
	headerCh     chan abey.DataPack        // [eth/62] Channel receiving inbound block headers
	bodyCh       chan abey.DataPack        // [eth/62] Channel receiving inbound block bodies
	bodyWakeCh   chan bool                 // [eth/62] Channel to signal the block body fetcher of new tasks
	headerProcCh chan []*types.SnailHeader // [eth/62] Channel to feed the header processor new tasks

	// for stateFetcher
	stateSyncStart chan *stateSync
	trackStateReq  chan *stateReq
	stateCh        chan abey.DataPack // [eth/63] Channel receiving inbound node state data

	// Cancellation and termination
	cancelPeer string         // Identifier of the peer currently being used as the master (cancel on drop)
	cancelCh   chan struct{}  // Channel to cancel mid-flight syncs
	cancelLock sync.RWMutex   // Lock to protect the cancel channel and peer in delivers
	cancelWg   sync.WaitGroup // Make sure all fetcher goroutines have exited.

	quitCh   chan struct{} // Quit channel to signal termination
	quitLock sync.RWMutex  // Lock to prevent double closes

	// Testing hooks
	syncInitHook    func(uint64, uint64)       // Method to call upon initiating a new sync run
	bodyFetchHook   func([]*types.SnailHeader) // Method to call upon starting a block body fetch
	chainInsertHook func([]*abey.FetchResult)  // Method to call upon inserting a chain of blocks (possibly in multiple invocations)

	fastDown     *fastdownloader.Downloader
	remoteHeader *types.Header
}

// LightChain encapsulates functions required to synchronise a light chain.
type LightChain interface {
	// HasHeader verifies a header's presence in the local chain.
	HasHeader(common.Hash, uint64) bool

	// GetHeaderByHash retrieves a header from the local chain.
	GetHeaderByHash(common.Hash) *types.SnailHeader

	// CurrentHeader retrieves the head header from the local chain.
	CurrentHeader() *types.SnailHeader

	// GetTd returns the total difficulty of a local block.
	GetTd(common.Hash, uint64) *big.Int

	// InsertHeaderChain inserts a batch of headers into the local chain.
	InsertHeaderChain([]*types.SnailHeader, [][]*types.SnailHeader, int) (int, error)

	// Rollback removes a few recently added elements from the local chain.
	Rollback([]common.Hash)
}

// BlockChain encapsulates functions required to sync a (full or fast) blockchain.
type BlockChain interface {
	LightChain

	// HasBlock verifies a block's presence in the local chain.
	HasBlock(common.Hash, uint64) bool

	// GetBlockByHash retrieves a block from the local chain.
	GetBlockByHash(common.Hash) *types.SnailBlock

	// CurrentBlock retrieves the head block from the local chain.
	CurrentBlock() *types.SnailBlock

	// CurrentFastBlock retrieves the head fast block from the local chain.
	CurrentFastBlock() *types.SnailBlock

	// InsertChain inserts a batch of blocks into the local chain.
	InsertChain(types.SnailBlocks) (int, error)

	FastInsertChain(types.SnailBlocks) (int, error)

	HasConfirmedBlock(hash common.Hash, number uint64) bool

	GetFruitsHash(header *types.SnailHeader, fruits []*types.SnailBlock) common.Hash
}

// New creates a new downloader to fetch hashes and blocks from remote peers.
func New(mode SyncMode, checkpoint uint64, stateDb abeydb.Database, mux *event.TypeMux, chain BlockChain, lightchain LightChain, dropPeer abey.PeerDropFn, fdown *fastdownloader.Downloader) *Downloader {
	if lightchain == nil {
		lightchain = chain
	}

	dl := &Downloader{
		mode:           mode,
		stateDB:        stateDb,
		checkpoint:     checkpoint,
		queue:          newQueue(chain),
		peers:          abey.NewPeerSet(),
		rttEstimate:    uint64(rttMaxEstimate),
		rttConfidence:  uint64(1000000),
		blockchain:     chain,
		lightchain:     lightchain,
		dropPeer:       dropPeer,
		headerCh:       make(chan abey.DataPack, 1),
		bodyCh:         make(chan abey.DataPack, 1),
		bodyWakeCh:     make(chan bool, 1),
		headerProcCh:   make(chan []*types.SnailHeader, 1),
		quitCh:         make(chan struct{}),
		fastDown:       fdown,
		stateCh:        make(chan abey.DataPack),
		stateSyncStart: make(chan *stateSync),
		syncStatsState: stateSyncStats{
			processed: rawdb.ReadFastTrieProgress(stateDb),
		},
		trackStateReq: make(chan *stateReq),
	}

	go dl.qosTuner()
	go dl.stateFetcher()
	return dl

}

func (d *Downloader) SetHeader(remote *types.Header) {
	d.remoteHeader = remote
}

// Progress retrieves the synchronisation boundaries, specifically the origin
// block where synchronisation started at (may have failed/suspended); the block
// or header sync is currently at; and the latest known block which the sync targets.
//
// In addition, during the state download phase of fast synchronisation the number
// of processed and the total number of known states are also returned. Otherwise
// these are zero.
func (d *Downloader) Progress() abeychain.SyncProgress {
	// Lock the current stats and return the progress
	d.syncStatsLock.RLock()
	defer d.syncStatsLock.RUnlock()

	current := uint64(0)
	switch d.mode {
	case LightSync:
		current = d.lightchain.CurrentHeader().Number.Uint64()
	default:
		current = d.blockchain.CurrentBlock().NumberU64()
	}
	f_prog := d.fastDown.Progress()

	return abeychain.SyncProgress{
		StartingSnailBlock: d.syncStatsChainOrigin,
		CurrentSnailBlock:  current,
		HighestSnailBlock:  d.syncStatsChainHeight,

		StartingFastBlock: f_prog.StartingFastBlock,
		CurrentFastBlock:  f_prog.CurrentFastBlock,
		HighestFastBlock:  f_prog.HighestFastBlock,

		PulledStates: d.syncStatsState.processed,
		KnownStates:  d.syncStatsState.processed + d.syncStatsState.pending,
	}
}

// Synchronising returns whether the downloader is currently retrieving blocks.
func (d *Downloader) Synchronising() bool {
	return atomic.LoadInt32(&d.synchronising) > 0
}

// RegisterPeer injects a new download peer into the set of block source to be
// used for fetching hashes and blocks from.
func (d *Downloader) RegisterPeer(id string, version int, ip string, peer abey.Peer) error {
	logger := log.New("peer Snail", ip)
	logger.Trace("Registering sync peer")

	if err := d.peers.Register(newPeerConnection(id, version, peer, logger)); err != nil {
		logger.Error("Failed to register sync peer", "err", err)
		return err
	}

	d.qosReduceConfidence()
	return nil
}

// RegisterLightPeer injects a light client peer, wrapping it so it appears as a regular peer.
func (d *Downloader) RegisterLightPeer(id string, version int, ip string, peer abey.LightPeer) error {
	return d.RegisterPeer(id, version, ip, &lightPeerWrapper{peer})
}

// UnregisterPeer remove a peer from the known list, preventing any action from
// the specified peer. An effort is also made to return any pending fetches into
// the queue.
func (d *Downloader) UnregisterPeer(id string) error {
	// Unregister the peer from the active peer set and revoke any fetch tasks
	logger := log.New("peer Snail", id)
	logger.Trace("Unregistering sync snail peer")
	if err := d.peers.Unregister(id); err != nil {
		logger.Error("Failed to unregister sync peer", "err", err)
		return err
	}
	d.queue.Revoke(id)

	// If this peer was the master peer, abort sync immediately
	d.cancelLock.RLock()
	master := id == d.cancelPeer
	d.cancelLock.RUnlock()

	if master {
		d.cancel()
	}
	return nil
}

// Synchronise tries to sync up our local block chain with a remote peer, both
// adding various sanity checks as well as wrapping it with various log entries.
func (d *Downloader) Synchronise(id string, head common.Hash, td *big.Int, mode SyncMode) error {
	err := d.synchronise(id, head, td, mode)
	defer log.Debug("Snail Synchronise exit")
	switch err {
	case nil:
	case errBusy:
	case types.ErrSnailHeightNotYet:
	case errTimeout, errBadPeer, errStallingPeer, errUnsyncedPeer,
		errEmptyHeaderSet, errPeersUnavailable, errTooOld,
		errInvalidAncestor, errInvalidChain:
		log.Warn("Snail Synchronisation failed, dropping peer", "peer", id, "err", err)
		if d.dropPeer == nil {
			// The dropPeer method is nil when `--copydb` is used for a local copy.
			// Timeouts can occur if e.g. compaction hits at the wrong time, and can be ignored
			log.Warn("Snail Downloader wants to drop peer, but peerdrop-function is not set", "peer", id)
		} else {
			d.dropPeer(id, types.SDownloaderCall)
		}
	default:
		log.Warn("Snail Synchronisation failed, retrying", "err", err)
	}
	return err
}

// synchronise will select the peer and use it for synchronising. If an empty string is given
// it will use the best peer possible and synchronize if its TD is higher than our own. If any of the
// checks fail an error will be returned. This method is synchronous
func (d *Downloader) synchronise(id string, hash common.Hash, td *big.Int, mode SyncMode) error {
	// Mock out the synchronisation if testing

	if d.synchroniseMock != nil {
		return d.synchroniseMock(id, hash)
	}
	// Make sure only one goroutine is ever allowed past this point at once
	if !atomic.CompareAndSwapInt32(&d.synchronising, 0, 1) {
		return errBusy
	}
	defer atomic.StoreInt32(&d.synchronising, 0)

	// Post a user notification of the sync (only once per session)
	if atomic.CompareAndSwapInt32(&d.notified, 0, 1) {
		log.Info("Snail Block synchronisation started")
	}
	// Reset the queue, peer set and wake channels to clean any internal leftover state
	d.queue.Reset()
	d.peers.Reset()

	for _, ch := range []chan bool{d.bodyWakeCh} {
		select {
		case <-ch:
		default:
		}
	}
	for _, ch := range []chan abey.DataPack{d.headerCh, d.bodyCh} {
		for empty := false; !empty; {
			select {
			case <-ch:
			default:
				empty = true
			}
		}
	}
	for empty := false; !empty; {
		select {
		case <-d.headerProcCh:
		default:
			empty = true
		}
	}
	// Create cancel channel for aborting mid-flight and mark the master peer
	d.cancelLock.Lock()
	d.cancelCh = make(chan struct{})
	d.cancelPeer = id
	d.cancelLock.Unlock()

	defer d.Cancel() // No matter what, we can't leave the cancel channel open

	// Set the requested sync mode, unless it's forbidden
	d.mode = mode

	// Retrieve the origin peer and initiate the downloading process
	p := d.peers.Peer(id)
	if p == nil {
		log.Warn("Snail Synchronise err", "id", id)
		return errUnknownPeer
	}
	return d.syncWithPeer(p, hash, td)
}

// syncWithPeer starts a block synchronization based on the hash chain from the
// specified peer and head hash.
func (d *Downloader) syncWithPeer(p abey.PeerConnection, hash common.Hash, td *big.Int) (err error) {
	if p.GetVersion() < 62 {
		return errTooOld
	}

	log.Debug("Snail Synchronising with the network", "peer", p.GetID(), "abey", p.GetVersion(), "head", hash, "td", td, "mode", d.mode)
	defer func(start time.Time) {
		log.Debug("Snail Synchronisation terminated", "elapsed", time.Since(start))
	}(time.Now())

	// Look up the sync boundaries: the common ancestor and the target block
	latest, err := d.fetchHeight(p)
	if err != nil {
		return err
	}
	height := latest.Number.Uint64()

	origin, err := d.findAncestor(p, latest)
	if err != nil {
		return err
	}
	d.syncStatsLock.Lock()
	if d.syncStatsChainHeight <= origin || d.syncStatsChainOrigin > origin {
		d.syncStatsChainOrigin = origin
	}
	d.syncStatsChainHeight = height
	d.syncStatsLock.Unlock()

	// Ensure our origin point is below any fast sync pivot point
	pivot := uint64(0)

	d.committed = 1
	if d.mode == FastSync && pivot != 0 {
		d.committed = 0
	}

	// Initiate the sync using a concurrent header and content retrieval algorithm
	d.queue.Prepare(origin+1, d.mode)
	if d.syncInitHook != nil {
		d.syncInitHook(origin, height)
	}

	fetchers := []func() error{
		func() error { return d.fetchHeaders(p, origin+1, pivot) }, // Headers are always retrieved
		func() error { return d.fetchBodies(origin + 1) },          // Bodies are retrieved during normal and fast sync
		func() error { return d.processHeaders(origin+1, pivot, td) },
	}

	//p PeerConnection, hash common.Hash, td *big.Int mode SyncMode,origin uint64, height uint64
	fetchers = append(fetchers, func() error { return d.processFullSyncContent(p, hash, td, latest) })

	return d.spawnSync(fetchers)
}

// spawnSync runs d.process and all given fetcher functions to completion in
// separate goroutines, returning the first error that appears.
func (d *Downloader) spawnSync(fetchers []func() error) error {
	errc := make(chan error, len(fetchers))
	d.cancelWg.Add(len(fetchers))
	for _, fn := range fetchers {
		fn := fn
		go func() {
			defer d.cancelWg.Done()
			errc <- fn()
		}()
	}
	// Wait for the first error, then terminate the others.
	var err error
	for i := 0; i < len(fetchers); i++ {
		if i == len(fetchers)-1 {
			// Close the queue when all fetchers have exited.
			// This will cause the block processor to end when
			// it has processed the queue.
			d.queue.Close()
		}
		if err = <-errc; err != nil {
			break
		}
	}

	d.queue.Close()
	d.Cancel()
	return err
}

// cancel aborts all of the operations and resets the queue. However, cancel does
// not wait for the running download goroutines to finish. This method should be
// used when cancelling the downloads from inside the downloader.
func (d *Downloader) cancel() {
	// Close the current cancel channel
	d.cancelLock.Lock()
	if d.cancelCh != nil {
		select {
		case <-d.cancelCh:
			// Channel was already closed
		default:
			close(d.cancelCh)
		}
	}
	d.cancelLock.Unlock()
}

// Cancel aborts all of the operations and waits for all download goroutines to
// finish before returning.
func (d *Downloader) Cancel() {
	d.fastDown.Cancel()
	d.cancel()
	d.cancelWg.Wait()
}

// Terminate interrupts the downloader, canceling all pending operations.
// The downloader cannot be reused after calling Terminate.
func (d *Downloader) Terminate() {
	// Close the termination channel (make sure double close is allowed)
	d.quitLock.Lock()
	select {
	case <-d.quitCh:
	default:
		close(d.quitCh)
	}
	d.quitLock.Unlock()

	// Cancel any pending download requests
	d.Cancel()
}

// fetchHeight retrieves the head header of the remote peer to aid in estimating
// the total time a pending synchronisation would take.
func (d *Downloader) fetchHeight(p abey.PeerConnection) (*types.SnailHeader, error) {
	p.GetLog().Debug("Retrieving remote chain height")

	// Request the advertised remote head block and wait for the response
	head, _ := p.GetPeer().Head()
	go p.GetPeer().RequestHeadersByHash(head, 1, 0, false, false)

	ttl := d.requestTTL()
	timeout := time.After(ttl)
	for {
		select {
		case <-d.cancelCh:
			return nil, errCancelBlockFetch

		case packet := <-d.headerCh:
			// Discard anything not from the origin peer
			if packet.PeerId() != p.GetID() {
				log.Debug("Snail Received headers from incorrect peer", "peer", packet.PeerId())
				break
			}
			// Make sure the peer actually gave something valid
			headers := packet.(*headerPack).headers
			if len(headers) != 1 {
				p.GetLog().Debug("Multiple headers for single request", "headers", len(headers))
				return nil, errBadPeer
			}
			head := headers[0]
			if d.mode == FastSync && head.Number.Uint64() < d.checkpoint {
				p.GetLog().Warn("Remote head below checkpoint", "number", head.Number, "hash", head.Hash())
				return nil, errUnsyncedPeer
			}
			p.GetLog().Debug("Remote head header identified", "number", head.Number, "hash", head.Hash())
			return head, nil

		case <-timeout:
			p.GetLog().Debug("Waiting for head header timed out", "elapsed", ttl)
			return nil, errTimeout

		case <-d.bodyCh:
		}
	}
}

// calculateRequestSpan calculates what headers to request from a peer when trying to determine the
// common ancestor.
// It returns parameters to be used for peer.RequestHeadersByNumber:
//
//	from - starting block number
//	count - number of headers to request
//	skip - number of headers to skip
//
// and also returns 'max', the last block which is expected to be returned by the remote peers,
// given the (from,count,skip)
func calculateRequestSpan(remoteHeight, localHeight uint64) (int64, int, int, uint64) {
	var (
		from     int
		count    int
		MaxCount = MaxHeaderFetch / 16 //12
	)
	// requestHead is the highest block that we will ask for. If requestHead is not offset,
	// the highest block that we will get is 16 blocks back from head, which means we
	// will fetch 14 or 15 blocks unnecessarily in the case the height difference
	// between us and the peer is 1-2 blocks, which is most common
	requestHead := int(remoteHeight) - 1
	if requestHead < 0 {
		requestHead = 0
	}
	// requestBottom is the lowest block we want included in the query
	// Ideally, we want to include just below own head
	requestBottom := int(localHeight - 1)
	if requestBottom < 0 {
		requestBottom = 0
	}
	totalSpan := requestHead - requestBottom
	span := 1 + totalSpan/MaxCount
	if span < 2 {
		span = 2
	}
	if span > 16 {
		span = 16
	}

	count = 1 + totalSpan/span
	if count > MaxCount {
		count = MaxCount
	}
	if count < 2 {
		count = 2
	}
	from = requestHead - (count-1)*span
	if from < 0 {
		from = 0
	}
	max := from + (count-1)*span
	return int64(from), count, span - 1, uint64(max)
}

// findAncestor tries to locate the common ancestor link of the local chain and
// a remote peers blockchain. In the general case when our node was in sync and
// on the correct chain, checking the top N links should already get us a match.
// In the rare scenario when we ended up on a long reorganisation (i.e. none of
// the head links match), we do a binary search to find the common ancestor.
func (d *Downloader) findAncestor(p abey.PeerConnection, remoteHeader *types.SnailHeader) (uint64, error) {
	// Figure out the valid ancestor range to prevent rewrite attacks
	var (
		floor        = int64(-1)
		localHeight  uint64
		remoteHeight = remoteHeader.Number.Uint64()
	)

	switch d.mode {
	case LightSync:
		localHeight = d.lightchain.CurrentHeader().Number.Uint64()
	default:
		localHeight = d.blockchain.CurrentBlock().NumberU64()
	}

	p.GetLog().Debug("Looking for common ancestor", "local", localHeight, "remote", remoteHeight)
	if localHeight >= MaxForkAncestry || d.mode == LightSync {
		// We're above the max reorg threshold, find the earliest fork point
		floor = int64(localHeight - MaxForkAncestry)

		// If we're doing a light sync, ensure the floor doesn't go below the CHT, as
		// all headers before that point will be missing.
		if d.mode == LightSync {
			// If we dont know the current CHT position, find it
			if d.genesis == 0 {
				header := d.lightchain.CurrentHeader()
				for header != nil {
					d.genesis = header.Number.Uint64()
					if floor >= int64(d.genesis)-1 {
						break
					}
					header = d.lightchain.GetHeaderByHash(header.ParentHash)
				}
			}
			// We already know the "genesis" block number, cap floor to that
			if floor < int64(d.genesis)-1 {
				floor = int64(d.genesis) - 1
			}
		}
	}
	from, count, skip, max := calculateRequestSpan(remoteHeight, localHeight)

	p.GetLog().Trace("Span searching for common ancestor", "count", count, "from", from, "skip", skip)
	go p.GetPeer().RequestHeadersByNumber(uint64(from), count, skip, false, false)

	// Wait for the remote response to the head fetch
	number, hash := uint64(0), common.Hash{}

	ttl := d.requestTTL()
	timeout := time.After(ttl)

	for finished := false; !finished; {
		select {
		case <-d.cancelCh:
			return 0, errCancelHeaderFetch

		case packet := <-d.headerCh:
			// Discard anything not from the origin peer
			if packet.PeerId() != p.GetID() {
				p.GetLog().Debug("Received headers from incorrect peer", "peer", packet.PeerId())
				break
			}
			// Make sure the peer actually gave something valid
			headers := packet.(*headerPack).headers
			if len(headers) == 0 {
				p.GetLog().Warn("Empty head header set")
				return 0, errEmptyHeaderSet
			}
			// Make sure the peer's reply conforms to the request
			for i, header := range headers {
				expectNumber := from + int64(i)*int64((skip+1))
				if number := header.Number.Int64(); number != expectNumber {
					p.GetLog().Warn("Head headers broke chain ordering", "index", i, "requested", expectNumber, "received", number)
					return 0, errInvalidChain
				}
			}
			// Check if a common ancestor was found
			finished = true
			for i := len(headers) - 1; i >= 0; i-- {
				// Skip any headers that underflow/overflow our requested set
				if headers[i].Number.Int64() < from || headers[i].Number.Uint64() > max {
					continue
				}
				// Otherwise check if we already know the header or not
				h := headers[i].Hash()
				n := headers[i].Number.Uint64()

				var known bool
				switch d.mode {
				case LightSync:
					known = d.lightchain.HasHeader(h, n)
				default:
					known = d.blockchain.HasConfirmedBlock(h, n)
				}
				if known {
					number, hash = n, h
					break
				}
			}

		case <-timeout:
			p.GetLog().Debug("Waiting for head header timed out", "elapsed", ttl)
			return 0, errTimeout

		case <-d.bodyCh:
			// Out of bounds delivery, ignore
		}
	}
	// If the head fetch already found an ancestor, return
	if hash != (common.Hash{}) {
		if int64(number) <= floor {
			p.GetLog().Warn("Ancestor below allowance", "number", number, "hash", hash, "allowance", floor)
			return 0, errInvalidAncestor
		}
		p.GetLog().Debug("Found common ancestor", "number", number, "hash", hash)
		return number, nil
	}
	// Ancestor not found, we need to binary search over our chain
	start, end := uint64(0), remoteHeight
	if floor > 0 {
		start = uint64(floor)
	}
	p.GetLog().Trace("Binary searching for common ancestor", "start", start, "end", end)

	for start+1 < end {
		// Split our chain interval in two, and request the hash to cross check
		check := (start + end) / 2

		ttl := d.requestTTL()
		timeout := time.After(ttl)

		go p.GetPeer().RequestHeadersByNumber(check, 1, 0, false, false)

		// Wait until a reply arrives to this request
		for arrived := false; !arrived; {
			select {
			case <-d.cancelCh:
				return 0, errCancelHeaderFetch

			case packer := <-d.headerCh:
				// Discard anything not from the origin peer
				if packer.PeerId() != p.GetID() {
					p.GetLog().Debug("Received headers from incorrect peer", "peer", packer.PeerId())
					break
				}
				// Make sure the peer actually gave something valid
				headers := packer.(*headerPack).headers
				if len(headers) != 1 {
					p.GetLog().Debug("Multiple headers for single request", "headers", len(headers))
					return 0, errBadPeer
				}
				arrived = true

				// Modify the search interval based on the response
				h := headers[0].Hash()
				n := headers[0].Number.Uint64()

				var known bool
				switch d.mode {
				case LightSync:
					known = d.lightchain.HasHeader(h, n)
				default:
					known = d.blockchain.HasConfirmedBlock(h, n)
				}
				if !known {
					end = check
					break
				}
				header := d.lightchain.GetHeaderByHash(h) // Independent of sync mode, header surely exists
				if header.Number.Uint64() != check {
					p.GetLog().Debug("Received non requested header", "number", header.Number, "hash", header.Hash(), "request", check)
					return 0, errBadPeer
				}
				start = check
				hash = h

			case <-timeout:
				p.GetLog().Debug("Waiting for search header timed out", "elapsed", ttl)
				return 0, errTimeout

			case <-d.bodyCh:
				// Out of bounds delivery, ignore
			}
		}
	}
	// Ensure valid ancestry and return
	if int64(start) <= floor {
		p.GetLog().Warn("Ancestor below allowance", "number", start, "hash", hash, "allowance", floor)
		return 0, errInvalidAncestor
	}
	p.GetLog().Debug("Found common ancestor", "number", start, "hash", hash)
	return start, nil
}

// fetchHeaders keeps retrieving headers concurrently from the number
// requested, until no more are returned, potentially throttling on the way. To
// facilitate concurrency but still protect against malicious nodes sending bad
// headers, we construct a header chain skeleton using the "origin" peer we are
// syncing with, and fill in the missing headers using anyone else. Headers from
// other peers are only accepted if they map cleanly to the skeleton. If no one
// can fill in the skeleton - not even the origin peer - it's assumed invalid and
// the origin is dropped.
func (d *Downloader) fetchHeaders(p abey.PeerConnection, from uint64, pivot uint64) error {
	p.GetLog().Debug("Directing header downloads", "origin", from, "pivot", pivot)
	defer p.GetLog().Debug("Header download terminated")

	// Create a timeout timer, and the associated header fetcher
	skeleton := true            // Skeleton assembly phase or finishing up
	request := time.Now()       // time of the last skeleton fetch request
	timeout := time.NewTimer(0) // timer to dump a non-responsive active peer
	<-timeout.C                 // timeout channel should be initially empty
	defer timeout.Stop()

	var ttl time.Duration
	getHeaders := func(from uint64) {
		request = time.Now()

		ttl = d.requestTTL()
		timeout.Reset(ttl)

		if skeleton {
			p.GetLog().Trace("Fetching skeleton headers", "count", MaxHeaderFetch, "from", from)
			go p.GetPeer().RequestHeadersByNumber(from+uint64(MaxHeaderFetch)-1, MaxSkeletonSize, MaxHeaderFetch-1, false, false)
		} else {
			p.GetLog().Trace("Fetching full headers", "count", MaxHeaderFetch, "from", from)
			go p.GetPeer().RequestHeadersByNumber(from, MaxHeaderFetch, 0, false, false)
		}
	}
	// Start pulling the header chain skeleton until all is done
	getHeaders(from)

	for {
		select {
		case <-d.cancelCh:
			return errCancelHeaderFetch

		case packet := <-d.headerCh:
			// Make sure the active peer is giving us the skeleton headers
			if packet.PeerId() != p.GetID() {
				p.GetLog().Debug("Received skeleton from incorrect peer", "peer", packet.PeerId())
				break
			}
			headerReqTimer.UpdateSince(request)
			timeout.Stop()

			// If the skeleton's finished, pull any remaining head headers directly from the origin
			if packet.Items() == 0 && skeleton {
				skeleton = false
				getHeaders(from)
				continue
			}
			// If no more headers are inbound, notify the content fetchers and return
			if packet.Items() == 0 {
				// Don't abort header fetches while the pivot is downloading
				if atomic.LoadInt32(&d.committed) == 0 && pivot <= from {
					p.GetLog().Debug("No headers, waiting for pivot commit")
					select {
					case <-time.After(fsHeaderContCheck):
						getHeaders(from)
						continue
					case <-d.cancelCh:
						return errCancelHeaderFetch
					}
				}
				// Pivot done (or not in fast sync) and no more headers, terminate the process
				p.GetLog().Debug("No more headers available")
				select {
				case d.headerProcCh <- nil:
					return nil
				case <-d.cancelCh:
					return errCancelHeaderFetch
				}
			}
			headers := packet.(*headerPack).headers

			// If we received a skeleton batch, resolve internals concurrently
			if skeleton {
				filled, proced, err := d.fillHeaderSkeleton(from, headers)
				if err != nil {
					p.GetLog().Warn("Skeleton chain invalid", "err", err)
					return errInvalidChain
				}
				headers = filled[proced:]
				from += uint64(proced)
			} else {
				// If we're closing in on the chain head, but haven't yet reached it, delay
				// the last few headers so mini reorgs on the head don't cause invalid hash
				// chain errors.
				if n := len(headers); n > 0 {
					// Retrieve the current head we're at
					head := uint64(0)
					if d.mode == LightSync {
						head = d.lightchain.CurrentHeader().Number.Uint64()
					} else {
						head = d.blockchain.CurrentFastBlock().NumberU64()
						if full := d.blockchain.CurrentBlock().NumberU64(); head < full {
							head = full
						}
					}
					// If the head is way older than this batch, delay the last few headers
					if head+uint64(reorgProtThreshold) < headers[n-1].Number.Uint64() {
						delay := reorgProtHeaderDelay
						if delay > n {
							delay = n
						}
						headers = headers[:n-delay]
					}
				}
			}
			// Insert all the new headers and fetch the next batch
			if len(headers) > 0 {
				p.GetLog().Trace("Scheduling new headers", "count", len(headers), "from", from)
				select {
				case d.headerProcCh <- headers:
				case <-d.cancelCh:
					return errCancelHeaderFetch
				}
				from += uint64(len(headers))
				getHeaders(from)
			} else {
				// No headers delivered, or all of them being delayed, sleep a bit and retry
				p.GetLog().Trace("All headers delayed, waiting")
				select {
				case <-time.After(fsHeaderContCheck):
					getHeaders(from)
					continue
				case <-d.cancelCh:
					return errCancelHeaderFetch
				}
			}

		case <-timeout.C:
			if d.dropPeer == nil {
				// The dropPeer method is nil when `--copydb` is used for a local copy.
				// Timeouts can occur if e.g. compaction hits at the wrong time, and can be ignored
				p.GetLog().Warn("Downloader wants to drop peer, but peerdrop-function is not set", "peer", p.GetID())
				break
			}
			// Header retrieval timed out, consider the peer bad and drop
			p.GetLog().Debug("Header request timed out", "elapsed", ttl)
			headerTimeoutMeter.Mark(1)
			d.dropPeer(p.GetID(), types.SDownloaderFetchCall)

			// Finish the sync gracefully instead of dumping the gathered data though
			for _, ch := range []chan bool{d.bodyWakeCh} {
				select {
				case ch <- false:
				case <-d.cancelCh:
				}
			}
			select {
			case d.headerProcCh <- nil:
			case <-d.cancelCh:
			}
			return errBadPeer
		}
	}
}

// fillHeaderSkeleton concurrently retrieves headers from all our available peers
// and maps them to the provided skeleton header chain.
//
// Any partial results from the beginning of the skeleton is (if possible) forwarded
// immediately to the header processor to keep the rest of the pipeline full even
// in the case of header stalls.
//
// The method returns the entire filled skeleton and also the number of headers
// already forwarded for processing.
func (d *Downloader) fillHeaderSkeleton(from uint64, skeleton []*types.SnailHeader) ([]*types.SnailHeader, int, error) {
	log.Debug("Snail Filling up skeleton", "from", from)
	d.queue.ScheduleSkeleton(from, skeleton)

	var (
		deliver = func(packet abey.DataPack) (int, error) {
			pack := packet.(*headerPack)
			return d.queue.DeliverHeaders(pack.peerID, pack.headers, d.headerProcCh)
		}
		expire   = func() map[string]int { return d.queue.ExpireHeaders(d.requestTTL()) }
		throttle = func() bool { return false }
		reserve  = func(p abey.PeerConnection, count int) (*abey.FetchRequest, bool, error) {
			return d.queue.ReserveHeaders(p, count), false, nil
		}
		fetch = func(p abey.PeerConnection, req *abey.FetchRequest) error {
			return p.FetchHeaders(req.From, MaxHeaderFetch)
		}
		capacity = func(p abey.PeerConnection) int { return p.HeaderCapacity(d.requestRTT()) }
		setIdle  = func(p abey.PeerConnection, accepted int) { p.SetHeadersIdle(accepted) }
	)
	err := d.fetchParts(errCancelHeaderFetch, d.headerCh, deliver, d.queue.headerContCh, expire,
		d.queue.PendingHeaders, d.queue.InFlightHeaders, throttle, reserve,
		nil, fetch, d.queue.CancelHeaders, capacity, d.peers.HeaderIdlePeers, setIdle, "headers")

	log.Debug("Snail Skeleton fill terminated", "err", err)

	filled, proced := d.queue.RetrieveHeaders()
	return filled, proced, err
}

// fetchBodies iteratively downloads the scheduled block bodies, taking any
// available peers, reserving a chunk of blocks for each, waiting for delivery
// and also periodically checking for timeouts.
func (d *Downloader) fetchBodies(from uint64) error {
	log.Debug("Snail Downloading block bodies", "origin", from)

	var (
		deliver = func(packet abey.DataPack) (int, error) {
			pack := packet.(*bodyPack)
			return d.queue.DeliverBodies(pack.peerID, pack.fruit)
		}
		expire   = func() map[string]int { return d.queue.ExpireBodies(d.requestTTL()) }
		fetch    = func(p abey.PeerConnection, req *abey.FetchRequest) error { return p.FetchBodies(req) }
		capacity = func(p abey.PeerConnection) int { return p.BlockCapacity(d.requestRTT()) }
		setIdle  = func(p abey.PeerConnection, accepted int) { p.SetBodiesIdle(accepted) }
	)
	err := d.fetchParts(errCancelBodyFetch, d.bodyCh, deliver, d.bodyWakeCh, expire,
		d.queue.PendingBlocks, d.queue.InFlightBlocks, d.queue.ShouldThrottleBlocks, d.queue.ReserveBodies,
		d.bodyFetchHook, fetch, d.queue.CancelBodies, capacity, d.peers.BodyIdlePeers, setIdle, "bodies")

	log.Debug("Snail Block body download terminated", "err", err)
	return err
}

// fetchParts iteratively downloads scheduled block parts, taking any available
// peers, reserving a chunk of fetch requests for each, waiting for delivery and
// also periodically checking for timeouts.
//
// As the scheduling/timeout logic mostly is the same for all downloaded data
// types, this method is used by each for data gathering and is instrumented with
// various callbacks to handle the slight differences between processing them.
//
// The instrumentation parameters:
//   - errCancel:   error type to return if the fetch operation is cancelled (mostly makes logging nicer)
//   - deliveryCh:  channel from which to retrieve downloaded data packets (merged from all concurrent peers)
//   - deliver:     processing callback to deliver data packets into type specific download queues (usually within `queue`)
//   - wakeCh:      notification channel for waking the fetcher when new tasks are available (or sync completed)
//   - expire:      task callback method to abort requests that took too long and return the faulty peers (traffic shaping)
//   - pending:     task callback for the number of requests still needing download (detect completion/non-completability)
//   - inFlight:    task callback for the number of in-progress requests (wait for all active downloads to finish)
//   - throttle:    task callback to check if the processing queue is full and activate throttling (bound memory use)
//   - reserve:     task callback to reserve new download tasks to a particular peer (also signals partial completions)
//   - fetchHook:   tester callback to notify of new tasks being initiated (allows testing the scheduling logic)
//   - fetch:       network callback to actually send a particular download request to a physical remote peer
//   - cancel:      task callback to abort an in-flight download request and allow rescheduling it (in case of lost peer)
//   - capacity:    network callback to retrieve the estimated type-specific bandwidth capacity of a peer (traffic shaping)
//   - idle:        network callback to retrieve the currently (type specific) idle peers that can be assigned tasks
//   - setIdle:     network callback to set a peer back to idle and update its estimated capacity (traffic shaping)
//   - kind:        textual label of the type being downloaded to display in log mesages
func (d *Downloader) fetchParts(errCancel error, deliveryCh chan abey.DataPack, deliver func(abey.DataPack) (int, error), wakeCh chan bool,
	expire func() map[string]int, pending func() int, inFlight func() bool, throttle func() bool, reserve func(abey.PeerConnection, int) (*abey.FetchRequest, bool, error),
	fetchHook func([]*types.SnailHeader), fetch func(abey.PeerConnection, *abey.FetchRequest) error, cancel func(*abey.FetchRequest), capacity func(abey.PeerConnection) int,
	idle func() ([]abey.PeerConnection, int), setIdle func(abey.PeerConnection, int), kind string) error {

	// Create a ticker to detect expired retrieval tasks
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	update := make(chan struct{}, 1)

	// Prepare the queue and fetch block parts until the block header fetcher's done
	finished := false
	for {
		select {
		case <-d.cancelCh:
			return errCancel

		case packet := <-deliveryCh:
			// If the peer was previously banned and failed to deliver its pack
			// in a reasonable time frame, ignore its message.
			log.Debug("Snail deliver", "id", packet.PeerId(), "type", kind, "pending", pending(), "count", packet.Stats())
			if peer := d.peers.Peer(packet.PeerId()); peer != nil {
				// Deliver the received chunk of data and check chain validity
				accepted, err := deliver(packet)
				if err == errInvalidChain {
					return err
				}
				// Unless a peer delivered something completely else than requested (usually
				// caused by a timed out request which came through in the end), set it to
				// idle. If the delivery's stale, the peer should have already been idled.
				if err != errStaleDelivery {
					setIdle(peer, accepted)
				}
				// Issue a log to the user to see what's going on
				switch {
				case err == nil && packet.Items() == 0:
					peer.GetLog().Trace("Requested snail data not delivered", "type", kind)
				case err == nil:
					peer.GetLog().Trace("Delivered new batch of snail data", "type", kind, "count", packet.Stats(), "pending", pending())
				default:
					peer.GetLog().Trace("Failed to deliver retrieved snail data", "type", kind, "err", err)
				}
			}
			// Blocks assembled, try to update the progress
			select {
			case update <- struct{}{}:
			default:
			}

		case cont := <-wakeCh:
			// The header fetcher sent a continuation flag, check if it's done
			if !cont {
				finished = true
			}
			// Headers arrive, try to update the progress
			select {
			case update <- struct{}{}:
			default:
			}

		case <-ticker.C:
			// Sanity check update the progress
			select {
			case update <- struct{}{}:
			default:
			}

		case <-update:
			// Short circuit if we lost all our peers
			if d.peers.Len() == 0 {
				return errNoPeers
			}
			// Check for fetch request timeouts and demote the responsible peers
			for pid, fails := range expire() {
				if peer := d.peers.Peer(pid); peer != nil {
					// If a lot of retrieval elements expired, we might have overestimated the remote peer or perhaps
					// ourselves. Only reset to minimal throughput but don't drop just yet. If even the minimal times
					// out that sync wise we need to get rid of the peer.
					//
					// The reason the minimum threshold is 2 is because the downloader tries to estimate the bandwidth
					// and latency of a peer separately, which requires pushing the measures capacity a bit and seeing
					// how response times reacts, to it always requests one more than the minimum (i.e. min 2).
					if fails > 2 {
						peer.GetLog().Trace("Data delivery timed out", "type", kind)
						setIdle(peer, 0)
					} else {
						peer.GetLog().Debug("Stalling delivery,snail dropping", "type", kind)
						if d.dropPeer == nil {
							// The dropPeer method is nil when `--copydb` is used for a local copy.
							// Timeouts can occur if e.g. compaction hits at the wrong time, and can be ignored
							peer.GetLog().Warn("Downloader wants to drop peer, but peerdrop-function is not set", "peer", pid)
						} else {
							peer.GetLog().Warn("drop peer snail fetchParts", "id", peer.GetPeer(), "type", kind, "fails", fails)
							d.dropPeer(pid, types.SDownloaderPartCall)
						}
					}
				}
			}
			// If there's nothing more to fetch, wait or terminate
			if pending() == 0 {
				if !inFlight() && finished {
					log.Debug("Snail Data fetching completed", "type", kind)
					return nil
				}
				break
			}
			// Send a download request to all idle peers, until throttled
			progressed, throttled, running := false, false, inFlight()
			idles, total := idle()

			for _, peer := range idles {
				// Short circuit if throttling activated
				if throttle() {
					throttled = true
					break
				}
				// Short circuit if there is no more available task.
				if pending() == 0 {
					break
				}
				// Reserve a chunk of fetches for a peer. A nil can mean either that
				// no more headers are available, or that the peer is known not to
				// have them.
				request, progress, err := reserve(peer, capacity(peer))
				if err != nil {
					return err
				}
				if progress {
					progressed = true
				}
				if request == nil {
					continue
				}
				if request.From > 0 {
					peer.GetLog().Trace("Requesting new batch of data", "type", kind, "pending", pending(), "progress", progress, "from", request.From)
				} else {
					peer.GetLog().Trace("Requesting new batch of data", "type", kind, "pending", pending(), "count", len(request.Sheaders), "progress", progress, "from", request.Sheaders[0].Number)
				}
				// Fetch the chunk and make sure any errors return the hashes to the queue
				if fetchHook != nil {
					fetchHook(request.Sheaders)
				}
				if err := fetch(peer, request); err != nil {
					// Although we could try and make an attempt to fix this, this error really
					// means that we've double allocated a fetch task to a peer. If that is the
					// case, the internal state of the downloader and the queue is very wrong so
					// better hard crash and note the error instead of silently accumulating into
					// a much bigger issue.
					panic(fmt.Sprintf("Snail %v: %s fetch assignment failed", peer, kind))
				}
				running = true
			}
			// Make sure that we have peers available for fetching. If all peers have been tried
			// and all failed throw an error
			if !progressed && !throttled && !running && len(idles) == total && pending() > 0 {
				return errPeersUnavailable
			}
		}
	}
}

// processHeaders takes batches of retrieved headers from an input channel and
// keeps processing and scheduling them into the header chain and downloader's
// queue until the stream ends or a failure occurs.
func (d *Downloader) processHeaders(origin uint64, pivot uint64, td *big.Int) error {
	// Keep a count of uncertain headers to roll back
	rollback := []*types.SnailHeader{}
	defer func() {
		if len(rollback) > 0 {
			// Flatten the headers and roll them back
			hashes := make([]common.Hash, len(rollback))
			for i, header := range rollback {
				hashes[i] = header.Hash()
			}
			lastHeader, lastFastBlock, lastBlock := d.lightchain.CurrentHeader().Number, common.Big0, common.Big0
			if d.mode != LightSync {
				lastFastBlock = d.blockchain.CurrentFastBlock().Number()
				lastBlock = d.blockchain.CurrentBlock().Number()
			}
			d.lightchain.Rollback(hashes)
			curFastBlock, curBlock := common.Big0, common.Big0
			if d.mode != LightSync {
				curFastBlock = d.blockchain.CurrentFastBlock().Number()
				curBlock = d.blockchain.CurrentBlock().Number()
			}
			log.Warn("Snail Rolled back headers", "count", len(hashes),
				"header", fmt.Sprintf("%d->%d", lastHeader, d.lightchain.CurrentHeader().Number),
				"fast", fmt.Sprintf("%d->%d", lastFastBlock, curFastBlock),
				"block", fmt.Sprintf("%d->%d", lastBlock, curBlock))
		}
	}()

	// Wait for batches of headers to process
	gotHeaders := false

	for {
		select {
		case <-d.cancelCh:
			return errCancelHeaderProcessing

		case headers := <-d.headerProcCh:
			log.Debug("ProcessHeaders Snail Terminate", "headers", len(headers), "headerProcCh", len(d.headerProcCh), "PendingBlocks", d.queue.PendingBlocks())
			// Terminate header processing if we synced up
			if len(headers) == 0 {
				// Notify everyone that headers are fully processed
				for _, ch := range []chan bool{d.bodyWakeCh} {
					select {
					case ch <- false:
					case <-d.cancelCh:
					}
				}
				// If no headers were retrieved at all, the peer violated its TD promise that it had a
				// better chain compared to ours. The only exception is if its promised blocks were
				// already imported by other means (e.g. fecher):
				//
				// R <remote peer>, L <local node>: Both at block 10
				// R: Mine block 11, and propagate it to L
				// L: Queue block 11 for import
				// L: Notice that R's head and TD increased compared to ours, start sync
				// L: Import of block 11 finishes
				// L: Sync begins, and finds common ancestor at 11
				// L: Request new headers up from 11 (R's TD was higher, it must have something)
				// R: Nothing to give
				if d.mode != LightSync {
					head := d.blockchain.CurrentBlock()
					if !gotHeaders && td.Cmp(d.blockchain.GetTd(head.Hash(), head.NumberU64())) > 0 {
						return errStallingPeer
					}
				}
				// If fast or light syncing, ensure promised headers are indeed delivered. This is
				// needed to detect scenarios where an attacker feeds a bad pivot and then bails out
				// of delivering the post-pivot blocks that would flag the invalid content.
				//
				// This check cannot be executed "as is" for full imports, since blocks may still be
				// queued for processing when the header download completes. However, as long as the
				// peer gave us something useful, we're already happy/progressed (above check).
				if d.mode == LightSync {
					head := d.lightchain.CurrentHeader()
					if !gotHeaders && td.Cmp(d.lightchain.GetTd(head.Hash(), head.Number.Uint64())) > 0 {
						return errStallingPeer
					}
				}
				// Disable any rollback and return
				rollback = nil
				return nil
			}
			// Otherwise split the chunk of headers into batches and process them
			gotHeaders = true

			for len(headers) > 0 {
				// Terminate if something failed in between processing chunks
				select {
				case <-d.cancelCh:
					return errCancelHeaderProcessing
				default:
				}
				// Select the next chunk of headers to import
				limit := maxHeadersProcess
				if limit > len(headers) {
					limit = len(headers)
				}
				chunk := headers[:limit]

				// If we've reached the allowed number of pending headers, stall a bit
				for d.queue.PendingBlocks() >= maxQueuedHeaders {
					select {
					case <-d.cancelCh:
						return errCancelHeaderProcessing
					case <-time.After(time.Second):
					}
				}
				// Otherwise insert the headers for content retrieval
				inserts := d.queue.Schedule(chunk, origin)
				if len(inserts) != len(chunk) {
					log.Debug("Snail Stale headers")
					return errBadPeer
				}
				headers = headers[limit:]
				origin += uint64(limit)
			}

			// Update the highest block number we know if a higher one is found.
			d.syncStatsLock.Lock()
			if d.syncStatsChainHeight < origin {
				d.syncStatsChainHeight = origin - 1
			}
			d.syncStatsLock.Unlock()
			log.Debug("ProcessHeaders snail over", "headers", len(headers), "origin", origin)
			// Signal the content downloaders of the availablility of new tasks
			for _, ch := range []chan bool{d.bodyWakeCh} {
				select {
				case ch <- true:
				default:
				}
			}
		}
	}
}

// processFullSyncContent takes fetch results from the queue and imports them into the chain.
func (d *Downloader) processFullSyncContent(p abey.PeerConnection, hash common.Hash, td *big.Int, remoteHeader *types.SnailHeader) error {

	var (
		stateSync *stateSync
	)

	if d.mode == FastSync || d.mode == SnapShotSync {
		stateSync = d.SyncState(d.remoteHeader.Root)
		d.fastDown.SetSync(stateSync)
		defer stateSync.Cancel()
		go func() {
			if err := stateSync.Wait(); err != nil && err != abey.ErrCancelStateFetch {
				d.queue.Close() // wake up Results
			}
		}()
	}

	for {
		results := d.queue.Results(true)
		if len(results) == 0 {
			return nil
		}

		if d.chainInsertHook != nil {
			d.chainInsertHook(results)
		}
		if err := d.importBlockResults(results, p, hash, td, remoteHeader); err != nil {
			return err
		}

	}
}

func (d *Downloader) importBlockResults(results []*abey.FetchResult, p abey.PeerConnection, hash common.Hash, td *big.Int, remoteHeader *types.SnailHeader) error {
	// Check for any early termination requests
	if len(results) == 0 {
		return nil
	}
	select {
	case <-d.quitCh:
		return errCancelContentProcessing
	default:
	}
	// Retrieve the a batch of results to import
	first, last := results[0].Sheader, results[len(results)-1].Sheader
	log.Info("Snail insert download chain", "results", len(results),
		"firstnum", first.Number, "firsthash", first.Hash(),
		"lastnum", last.Number, "lasthash", last.Hash(), "mode", d.mode,
		"current", d.blockchain.CurrentHeader().Number)
	sblocks := []*types.SnailBlock{}
	for _, result := range results {
		block := types.NewSnailBlockWithHeader(result.Sheader).WithBody(result.Fruits, nil)
		fruitLen := uint64(len(result.Fruits))
		if fruitLen > 0 {
			fbNumber := result.Fruits[0].FastNumber().Uint64()
			fbLastNumber := result.Fruits[fruitLen-1].FastNumber().Uint64()

			if fbLastNumber < fbNumber || fbNumber < 1 {
				return errFruits
			}
			sblocks = append(sblocks, block)
		}
	}

	txLen := len(sblocks)
	if d.mode == LightSync {
		if err := d.importBlockAndSyncFast(sblocks, p, hash); err != nil {
			return err
		}
	} else {
		maxSize := int(maxSyncSnailHeight)
		if txLen > maxSize {
			for i := 0; i < txLen; {
				i = i + maxSize
				if i <= txLen {
					if err := d.importBlockAndSyncFast(sblocks[:maxSize], p, hash); err != nil {
						return err
					}
					sblocks = append(sblocks[:0], sblocks[maxSize:]...)
				} else {
					if err := d.importBlockAndSyncFast(sblocks[:txLen%maxSize], p, hash); err != nil {
						return err
					}
				}
			}
		} else if len(sblocks) > 0 {
			if err := d.importBlockAndSyncFast(sblocks, p, hash); err != nil {
				return err
			}
		}
	}

	return nil
}

func (d *Downloader) importBlockAndSyncFast(blocks []*types.SnailBlock, p abey.PeerConnection, hash common.Hash) error {
	firstB := blocks[0]
	fbNumber := firstB.Fruits()[0].FastNumber().Uint64()

	result := blocks[len(blocks)-1]
	fruitLen := uint64(len(result.Fruits()))
	fbLastNumber := result.Fruits()[fruitLen-1].FastNumber().Uint64()
	log.Info("Sync fast blocks", "fbNumber", fbNumber, "fbLastNumber", fbLastNumber, "first snail", firstB.Number(), "last snail", result.Number(), "mode", d.mode)
	if err := d.SyncFast(p.GetID(), hash, fbLastNumber, d.mode); err != nil {
		return err
	}

	switch d.mode {
	case SnapShotSync, FastSync:
		if index, err := d.blockchain.FastInsertChain(blocks); err != nil {
			log.Error("Snail Fastdownloaded item processing failed", "number", blocks[index].NumberU64(), "hash", blocks[index].Hash(), "err", err)
			if err == types.ErrSnailHeightNotYet {
				return err
			}
			return errInvalidChain
		}
		return nil
	case FullSync:
		if index, err := d.blockchain.InsertChain(blocks); err != nil {
			log.Error("Snail downloaded item processing failed", "number", blocks[index].Number, "hash", blocks[index].Hash(), "err", err)
			if err == types.ErrSnailHeightNotYet {
				return err
			}
			return errInvalidChain
		}
	case LightSync:
		// Deliver them all to the downloader for queuing
		heads := make([]*types.SnailHeader, len(blocks))
		fruitHeads := make([][]*types.SnailHeader, len(blocks))

		for i, block := range blocks {
			heads[i] = block.Header()
			fruitHeads[i] = block.Body().FruitsHeaders()
		}

		maxSize := int(maxSyncSnailHeight) / 2
		txLen := len(heads)

		if txLen > maxSize {
			for i := 0; i < txLen; {
				i = i + maxSize
				if i <= txLen {
					if err := d.insertLightHeadChain(heads[:maxSize], fruitHeads[:maxSize]); err != nil {
						return err
					}
					heads = append(heads[:0], heads[maxSize:]...)
					fruitHeads = append(fruitHeads[:0], fruitHeads[maxSize:]...)
				} else {
					if err := d.insertLightHeadChain(heads[:txLen%maxSize], fruitHeads[:txLen%maxSize]); err != nil {
						return err
					}
				}
			}
		} else if len(blocks) > 0 {
			if err := d.insertLightHeadChain(heads, fruitHeads); err != nil {
				return err
			}
		}
	}

	return nil
}

func (d *Downloader) insertLightHeadChain(heads []*types.SnailHeader, fruitHeads [][]*types.SnailHeader) (err error) {
	if index, err := d.lightchain.InsertHeaderChain(heads, fruitHeads, 100); err != nil {
		log.Info("insertLightHeadChain", "index", index, "heads", len(heads), "err", err)
		log.Error("Snail downloaded item processing failed", "number", heads[index].Number, "hash", heads[index].Hash(), "err", err)
		if err == types.ErrSnailHeightNotYet {
			return err
		}
		return errInvalidChain
	}
	return nil
}

func (d *Downloader) SyncFast(peer string, remoteHeadHash common.Hash, remoteNumber uint64, mode SyncMode) (err error) {

	currentNumber := uint64(0)
	if d.mode == LightSync {
		currentNumber = d.fastDown.GetLightChain().CurrentHeader().Number.Uint64()
	} else {
		currentNumber = d.fastDown.GetBlockChain().CurrentBlock().NumberU64()
		if mode == FastSync {
			currentNumber = d.fastDown.GetBlockChain().CurrentFastBlock().NumberU64()
		} else if mode == SnapShotSync {
			currentNumber = d.fastDown.GetBlockChain().CurrentHeader().Number.Uint64()
		}
	}

	defer func(start time.Time) {
		log.Debug("SyncFast sync terminated", "elapsed", time.Since(start))
	}(time.Now())

	if remoteNumber > currentNumber {
		log.Debug("Run fast downloader ", "remote fast NumLast", remoteNumber, "currentNum", currentNumber, "mode", mode)
		if mode == SnapShotSync && remoteNumber > d.remoteHeader.Number.Uint64() {
			mode = FastSync
		}

		errs := d.fastDown.Synchronise(peer, remoteHeadHash, fastdownloader.SyncMode(mode), currentNumber, remoteNumber)

		if errs != nil {
			log.Error("SyncFast failed", "err", errs, "remote fast NumLast", remoteNumber, "currentNum", currentNumber)
			return errs
		}
	}
	return nil
}

// DeliverHeaders injects a new batch of block headers received from a remote
// node into the download schedule.
func (d *Downloader) DeliverHeaders(id string, headers []*types.SnailHeader) (err error) {
	return d.deliver(id, d.headerCh, &headerPack{id, headers}, headerInMeter, headerDropMeter)
}

// DeliverBodies injects a new batch of block bodies received from a remote node.
func (d *Downloader) DeliverBodies(id string, fruit [][]*types.SnailBlock) (err error) {
	return d.deliver(id, d.bodyCh, &bodyPack{id, fruit}, bodyInMeter, bodyDropMeter)
}

// DeliverNodeData injects a new batch of node state data received from a remote node.
func (d *Downloader) DeliverNodeData(id string, data [][]byte) (err error) {
	return d.deliver(id, d.stateCh, &statePack{id, data}, stateInMeter, stateDropMeter)
}

// deliver injects a new batch of data received from a remote node.
func (d *Downloader) deliver(id string, destCh chan abey.DataPack, packet abey.DataPack, inMeter, dropMeter metrics.Meter) (err error) {
	// Update the delivery metrics for both good and failed deliveries
	inMeter.Mark(int64(packet.Items()))
	defer func() {
		if err != nil {
			dropMeter.Mark(int64(packet.Items()))
		}
	}()
	// Deliver or abort if the sync is canceled while queuing
	d.cancelLock.RLock()
	cancel := d.cancelCh
	d.cancelLock.RUnlock()
	if cancel == nil {
		return errNoSyncActive
	}
	select {
	case destCh <- packet:
		return nil
	case <-cancel:
		return errNoSyncActive
	}
}

// qosTuner is the quality of service tuning loop that occasionally gathers the
// peer latency statistics and updates the estimated request round trip time.
func (d *Downloader) qosTuner() {
	for {
		// Retrieve the current median RTT and integrate into the previoust target RTT
		rtt := time.Duration((1-qosTuningImpact)*float64(atomic.LoadUint64(&d.rttEstimate)) + qosTuningImpact*float64(d.peers.MedianRTT()))
		atomic.StoreUint64(&d.rttEstimate, uint64(rtt))

		// A new RTT cycle passed, increase our confidence in the estimated RTT
		conf := atomic.LoadUint64(&d.rttConfidence)
		conf = conf + (1000000-conf)/2
		atomic.StoreUint64(&d.rttConfidence, conf)

		// Log the new QoS values and sleep until the next RTT
		log.Debug("Snail Recalculated downloader QoS values", "rtt", rtt, "confidence", float64(conf)/1000000.0, "ttl", d.requestTTL())
		select {
		case <-d.quitCh:
			return
		case <-time.After(rtt):
		}
	}
}

// qosReduceConfidence is meant to be called when a new peer joins the downloader's
// peer set, needing to reduce the confidence we have in out QoS estimates.
func (d *Downloader) qosReduceConfidence() {
	// If we have a single peer, confidence is always 1
	peers := uint64(d.peers.Len())
	if peers == 0 {
		// Ensure peer connectivity races don't catch us off guard
		return
	}
	if peers == 1 {
		atomic.StoreUint64(&d.rttConfidence, 1000000)
		return
	}
	// If we have a ton of peers, don't drop confidence)
	if peers >= uint64(qosConfidenceCap) {
		return
	}
	// Otherwise drop the confidence factor
	conf := atomic.LoadUint64(&d.rttConfidence) * (peers - 1) / peers
	if float64(conf)/1000000 < rttMinConfidence {
		conf = uint64(rttMinConfidence * 1000000)
	}
	atomic.StoreUint64(&d.rttConfidence, conf)

	rtt := time.Duration(atomic.LoadUint64(&d.rttEstimate))
	log.Debug("Snail Relaxed downloader QoS values", "rtt", rtt, "confidence", float64(conf)/1000000.0, "ttl", d.requestTTL())
}

// requestRTT returns the current target round trip time for a download request
// to complete in.
//
// Note, the returned RTT is .9 of the actually estimated RTT. The reason is that
// the downloader tries to adapt queries to the RTT, so multiple RTT values can
// be adapted to, but smaller ones are preferred (stabler download stream).
func (d *Downloader) requestRTT() time.Duration {
	return time.Duration(atomic.LoadUint64(&d.rttEstimate)) * 9 / 10
}

// requestTTL returns the current timeout allowance for a single download request
// to finish under.
func (d *Downloader) requestTTL() time.Duration {
	var (
		rtt  = time.Duration(atomic.LoadUint64(&d.rttEstimate))
		conf = float64(atomic.LoadUint64(&d.rttConfidence)) / 1000000.0
	)
	ttl := time.Duration(ttlScaling) * time.Duration(float64(rtt)/conf)
	if ttl > ttlLimit {
		ttl = ttlLimit
	}
	return ttl
}
