// Copyright 2017 The Celo Authors
// This file is part of the celo library.
//
// The celo library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The celo library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the celo library. If not, see <http://www.gnu.org/licenses/>.

package backend

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/istanbul"
	vet "github.com/ethereum/go-ethereum/consensus/istanbul/backend/internal/enodes"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/rlp"
)

// ==============================================
//
// define the constants and function for the sendAnnounce thread

const (
	announceGossipCooldownDuration = 5 * time.Minute
	// Schedule retries to be strictly later than the cooldown duration
	// that other nodes will impose for regossiping announces from this node.
	announceRetryDuration          = announceGossipCooldownDuration + (30 * time.Second)
	announceAnswerCooldownDuration = 5 * time.Minute

	signedAnnounceVersionGossipCooldownDuration = 5 * time.Minute
)

type announceHandler struct {
     sb *Backend

     announceValidatorSet map[common.Address]bool

     querySendTimestampHeap *timestampHeap

     threadRunning   bool
     threadRunningMu sync.RWMutex
     threadWg        *sync.WaitGroup
     threadQuit      chan struct{}
}

func newAnnounceHandler(sb *Backend) *announceHandler {
	return &announceHandler{
		sb:         sb,
		threadWg:   new(sync.WaitGroup),
		threadQuit: make(chan struct{}),
		querySendTimestampHeap: &timestampHeap{}
	}
}

type queryTimestampEntry struct {
     queryTimestamp int64
     recipientAddress common.Address
}

type queryTimestampHeap []*queryTimestampEntry

func (th timestampHeap) Len() int           { return len(th) }
func (th timestampHeap) Less(i, j int) bool { return th[i].queryTimestamp < th[j].queryTimestamp }
func (th timestampHeap) Swap(i, j int)      { th[i], th[j] = th[j], tth[i] }
func (th *timestampHeap) Push(x interface{}) { *th = append(*th, x.(*queryTimestampEntry)) }
func (th *timestampHeap) Pop() interface{} {
     old := *th
     n := len(old)
     x := old[n-1]
     *th = old[0 : n-1]
     return x
}

func (ah *announceHandler) startThread() error {
	ah.threadRunningMu.Lock()
	defer ah.threadRunningMu.Unlock()
	if ah.threadRunning {
		return istanbul.ErrStartedAHThread
	}

	go ah.thread()

	return nil
}

func (ah *announceHandler) stopThread() error {
	ah.threadRunningMu.Lock()
	defer ah.threadRunningMu.Unlock()

	if !ah.threadRunning {
		return istanbul.ErrStoppedAHThread
	}

	ah.threadQuit <- struct{}{}
	ah.threadWg.Wait()

	ah.threadRunning = false
	return nil
}


// The announceThread will:
// 1) Periodically generate the announceValidatorSet
// 2) Periodically poll to see if this node if part of the announceValidatorSet and if istanbul.core is started
// 2) For ALL nodes, periodically share the entire signed announce version table with all peers
// 3) For ALL nodes, periodically prune announce-related data structures
// 4) Gossip announce messages when requested
// 5) Retry sending announce messages if they go unanswered
// 6) Update announce version when requested
func (ah *announceHandler) thread() {
	logger := sb.logger.New("func", "announceThread")

	sb.announceThreadWg.Add(1)
	defer sb.announceThreadWg.Done()

	// Ticker to retrieve and cache the announce validator set.
	retrieveAndCacheAnnounceValSet := time.NewTicker(1 * time.Minute)

	// TODO: this can be removed once we have more faith in this protocol
	updateAnnounceVersionTicker := time.NewTicker(5 * time.Minute)
	
	// Periodically share the entire signed announce version table with all peers
	shareSignedAnnounceVersionTicker := time.NewTicker(5 * time.Minute)

	// Periodically prune the announce related data structures
	pruneAnnounceDataStructuresTicker := time.NewTicker(10 * time.Minute)

	// Periodically see if an announce query needs to be gossiped
	announceQueryTicker := time.NewTicker(6 * time.Minute)

	var announceVersion uint
	var publishingEnodeURL bool

	updateAnnounceVersionFunc := func() {
		version := newAnnounceVersion()
		if version <= announceVersion {
			logger.Debug("Announce version is not newer than the existing version", "existing version", announceVersion, "attempted new version", version)
			return
		}
		if err := sb.setAndShareUpdatedAnnounceVersion(version); err != nil {
			logger.Warn("Error updating announce version", "err", err)
			return
		}
		announceVersion = version
	}

	for {
		select {

		// Periodically retrieve and cache the announce validator set
		case <-retrieveAndCacheAnnounceValSet.C:
		        logger.Trace("Retrieving and caching the announce val set")
			newAnnounceValSet := ah.retrieveAnnounceValSet()
			ah.announceValSetMu.Lock()
			ah.announceValSet = newAnnounceValSet
			ah.announceValSetMu.UnLock()

		// Periodically check if this node should publish it's enodeURL to other validators within the announce validator set
		case <-checkIfShouldPublishEnodeURL.C:
			logger.Trace("Checking if this node should announce it's enode")
			shouldPublishEnodeURL := sb.coreStarted && ah.validatorConnSet[sb.Address()]

			// Send out a version message is this node just enabled publishing it's enodeURL
			if !publishingEnodeURL && shouldPublishEnodeURL {
			   ah.updateAnnounceVersionCh <- struct{}
			   publishingEnodeURL = true
			   logger.Trace("Started publishing enode URL")
			}

		// Periodically update this nodes's announce version number
		case <-updateAnnounceVersionTicker.C:
			if publishingEnodeURL {
			   ah.updateAnnounceVersionCh <- struct{}
			}

		// Periodically share this node's remove validators' enodeURL version
		case <-shareSignedAnnounceVersionTicker.C:
			// Send all signed announce versions to every peer. Only the entries
			// that are new to a node will end up being regossiped throughout the
			// network.
			allSignedAnnounceVersions, err := sb.getAllSignedAnnounceVersions()
			if err != nil {
				logger.Warn("Error getting all signed announce versions", "err", err)
				break
			}
			if err := sb.gossipSignedAnnounceVersionsMsg(allSignedAnnounceVersions); err != nil {
				logger.Warn("Error gossiping all signed announce versions")
			}

		// Periodically check to see if an announce query messages needs to be gossiped
		case <-announceQueryTicker.C:
		        if publishingEnodeURL {
			   // Create a slice of addresses of length 1, since only one address
			   // will most likely be popped from the heap.
			   remoteAddressesToQuery := make(common.Address[], 1)
			   currentTime := time.Unix()

			   // Pop off all of the entries with timestamps that are in the past
			   for len(querySendTimestampHeap) > 0 {
			       if querySendTimestampHeap[0].queryTimestamp <= currentTime {
			       	  append(remoteAddressesToQuery, *queryTimestampEntry(heap.Pop(querySendTimestampHeap)).recipientAddress)		  
			       }
			   }
			   
			   ah.gossipQueryAnnounceTask(remoteAddressesToQuery)
			}

		case <-sb.updateAnnounceVersionCh:
			updateAnnounceVersionFunc()
			sb.updateAnnounceVersionCompleteCh <- struct{}{}

		case <-pruneAnnounceDataStructuresTicker.C:
			if err := sb.pruneAnnounceDataStructures(); err != nil {
				logger.Warn("Error in pruning announce data structures", "err", err)
			}

		case <-sb.announceThreadQuit:
			checkIfShouldAnnounceTicker.Stop()
			pruneAnnounceDataStructuresTicker.Stop()
			return
		}
	}
}

func (sb *Backend) shouldGenerateAndProcessAnnounce() (bool, error) {
	// Check if this node is in the validator connection set
	validatorConnSet, err := sb.retrieveValidatorConnSet()
	if err != nil {
		return false, err
	}

	return sb.coreStarted && validatorConnSet[sb.Address()], nil
}

// pruneAnnounceDataStructures will remove entries that are not in the validator connection set from all announce related data structures.
// The data structures that it prunes are:
// 1)  lastAnnounceGossiped
// 2)  lastAnnounceAnswered
// 3)  valEnodeTable
// 4)  lastSignedAnnounceVersionsGossiped
// 5)  signedAnnounceVersionTable
func (sb *Backend) pruneAnnounceDataStructures() error {
	logger := sb.logger.New("func", "pruneAnnounceDataStructures")

	// retrieve the validator connection set
	validatorConnSet, err := sb.retrieveValidatorConnSet()
	if err != nil {
		return err
	}

	sb.lastAnnounceGossipedMu.Lock()
	for remoteAddress := range sb.lastAnnounceGossiped {
		if !validatorConnSet[remoteAddress] && time.Since(sb.lastAnnounceGossiped[remoteAddress].Time) >= announceGossipCooldownDuration {
			logger.Trace("Deleting entry from lastAnnounceGossiped", "address", remoteAddress, "gossip timestamp", sb.lastAnnounceGossiped[remoteAddress])
			delete(sb.lastAnnounceGossiped, remoteAddress)
		}
	}
	sb.lastAnnounceGossipedMu.Unlock()

	sb.lastAnnounceAnsweredMu.Lock()
	for remoteAddress := range sb.lastAnnounceAnswered {
		if !validatorConnSet[remoteAddress] && time.Since(sb.lastAnnounceAnswered[remoteAddress]) >= announceAnswerCooldownDuration {
			logger.Trace("Deleting entry from lastAnnounceAnswered", "address", remoteAddress, "answer timestamp", sb.lastAnnounceAnswered[remoteAddress])
			delete(sb.lastAnnounceAnswered, remoteAddress)
		}
	}
	sb.lastAnnounceAnsweredMu.Unlock()

	if err := sb.valEnodeTable.PruneEntries(validatorConnSet); err != nil {
		logger.Trace("Error in pruning valEnodeTable", "err", err)
		return err
	}

	sb.lastSignedAnnounceVersionsGossipedMu.Lock()
	for remoteAddress := range sb.lastSignedAnnounceVersionsGossiped {
		if !validatorConnSet[remoteAddress] && time.Since(sb.lastSignedAnnounceVersionsGossiped[remoteAddress]) >= signedAnnounceVersionGossipCooldownDuration {
			logger.Trace("Deleting entry from lastSignedAnnounceVersionsGossiped", "address", remoteAddress, "gossip timestamp", sb.lastSignedAnnounceVersionsGossiped[remoteAddress])
			delete(sb.lastSignedAnnounceVersionsGossiped, remoteAddress)
		}
	}
	sb.lastSignedAnnounceVersionsGossipedMu.Unlock()

	if err := sb.signedAnnounceVersionTable.Prune(validatorConnSet); err != nil {
		logger.Trace("Error in pruning signedAnnounceVersionTable", "err", err)
		return err
	}

	return nil
}

// ===============================================================
//
// define the IstanbulAnnounce message format, the AnnounceMsgCache entries, the announce send function (both the gossip version and the "retrieve from cache" version), and the announce get function

type announceRegossip struct {
	Time    time.Time
	Version uint
}

type scheduledAnnounceRegossip struct {
	Timer   *time.Timer
	Version uint
}

// answerAnnounceMsg will answer a received announce message from an origin
// node. If the node is already a peer of any kind, an enodeCertificate will be sent.
// Regardless, the origin node will be upserted into the val enode table
// to ensure this node designates the origin node as a ValidatorPurpose peer.
func (sb *Backend) answerAnnounceMsg(address common.Address, node *enode.Node, version uint) error {
	targetIDs := map[enode.ID]bool{
		node.ID(): true,
	}
	// The target could be an existing peer of any purpose.
	matches := sb.broadcaster.FindPeers(targetIDs, p2p.AnyPurpose)
	if matches[node.ID()] != nil {
		enodeCertificateMsg, err := sb.retrieveEnodeCertificateMsg()
		if err != nil {
			return err
		}
		if err := sb.sendEnodeCertificateMsg(matches[node.ID()], enodeCertificateMsg); err != nil {
			return err
		}
	}
	// Upsert regardless to account for the case that the target is a non-ValidatorPurpose
	// peer but should be.
	// If the target is not a peer and should be a ValidatorPurpose peer, this
	// will designate the target as a ValidatorPurpose peer and send an enodeCertificate
	// during the istanbul handshake.
	if err := sb.valEnodeTable.Upsert(map[common.Address]*vet.AddressEntry{address: {Node: node, Version: version}}); err != nil {
		return err
	}
	return nil
}

// validateAnnounce will do some validation to check the contents of the announce
// message. This is to force all validators that send an announce message to
// create as succint message as possible, and prevent any possible network DOS attacks
// via extremely large announce message.
func (sb *Backend) validateAnnounce(msgAddress common.Address, announceData *announceData) (bool, error) {
	logger := sb.logger.New("func", "validateAnnounce", "msg address", msgAddress)

	// Ensure the version in the announceData is not older than the signed
	// announce version if it is known by this node
	knownVersion, err := sb.signedAnnounceVersionTable.GetVersion(msgAddress)
	if err == nil && announceData.Version < knownVersion {
		logger.Debug("Announce message has version older than known version from signed announce table", "msg version", announceData.Version, "known version", knownVersion)
		return false, nil
	}

	// Check if there are any duplicates in the announce message
	var encounteredAddresses = make(map[common.Address]bool)
	for _, announceRecord := range announceData.AnnounceRecords {
		if encounteredAddresses[announceRecord.DestAddress] {
			logger.Info("Announce message has duplicate entries", "address", announceRecord.DestAddress)
			return false, nil
		}

		encounteredAddresses[announceRecord.DestAddress] = true
	}

	// Check if the number of rows in the announcePayload is at most 2 times the size of the current validator connection set.
	// Note that this is a heuristic of the actual size of validator connection set at the time the validator constructed the announce message.
	validatorConnSet, err := sb.retrieveValidatorConnSet()
	if err != nil {
		return false, err
	}

	if len(announceData.AnnounceRecords) > 2*len(validatorConnSet) {
		logger.Info("Number of announce message encrypted enodes is more than two times the size of the current validator connection set", "num announce enodes", len(announceData.AnnounceRecords), "reg/elected val set size", len(validatorConnSet))
		return false, err
	}

	return true, nil
}

// scheduleAnnounceRegossip schedules a regossip for an announce message after
// its cooldown period. If one is already scheduled, it's overwritten.
func (sb *Backend) scheduleAnnounceRegossip(msg *istanbul.Message, announceVersion uint, payload []byte) error {
	logger := sb.logger.New("func", "scheduleAnnounceRegossip", "msg address", msg.Address)
	sb.scheduledAnnounceRegossipsMu.Lock()
	defer sb.scheduledAnnounceRegossipsMu.Unlock()

	// If another announce version regossip has been scheduled for the message
	// address already, cancel it
	if scheduledRegossip := sb.scheduledAnnounceRegossips[msg.Address]; scheduledRegossip != nil {
		scheduledRegossip.Timer.Stop()
	}

	sb.lastAnnounceGossipedMu.RLock()
	versionedGossipTime := sb.lastAnnounceGossiped[msg.Address]
	if versionedGossipTime == nil {
		logger.Debug("Last announce gossiped not found")
		sb.lastAnnounceGossipedMu.RUnlock()
		return nil
	}
	scheduledTime := versionedGossipTime.Time.Add(announceGossipCooldownDuration)
	sb.lastAnnounceGossipedMu.RUnlock()

	duration := time.Until(scheduledTime)
	// If by this time the cooldown period has ended, just regossip
	if duration < 0 {
		return sb.regossipAnnounce(msg, announceVersion, payload, true)
	}
	regossipFunc := func() {
		if err := sb.regossipAnnounce(msg, announceVersion, payload, true); err != nil {
			logger.Debug("Error in scheduled announce regossip", "err", err)
		}
		sb.scheduledAnnounceRegossipsMu.Lock()
		delete(sb.scheduledAnnounceRegossips, msg.Address)
		sb.scheduledAnnounceRegossipsMu.Unlock()
	}
	sb.scheduledAnnounceRegossips[msg.Address] = &scheduledAnnounceRegossip{
		Timer:   time.AfterFunc(duration, regossipFunc),
		Version: announceVersion,
	}
	return nil
}

// regossipAnnounce will regossip a received announce message.
// If this node regossiped an announce from the same source address within the last
// 5 minutes, then it won't regossip. This is to prevent a malicious validator from
// DOS'ing the network with very frequent announce messages.
// This opens an attack vector where any malicious node could continue to gossip
// a previously gossiped announce message from any validator, causing other nodes to regossip and
// enforce the cooldown period for future messages originating from the origin validator.
// This could result in new legitimate announce messages from the origin validator
// not being regossiped due to the cooldown period enforced by the other nodes in
// the network.
// To ensure that a new legitimate message will eventually be gossiped to the rest
// of the network, we schedule an announce message with a new version that is
// received during the cooldown period to be sent after the cooldown period ends,
// and refuse to regossip old messages from the validator during that time.
// Providing `force` as true will skip any of the DOS checks.
func (sb *Backend) regossipAnnounce(msg *istanbul.Message, announceVersion uint, payload []byte, force bool) error {
	logger := sb.logger.New("func", "regossipAnnounce", "announceSourceAddress", msg.Address, "announceVersion", announceVersion)

	if !force {
		sb.scheduledAnnounceRegossipsMu.RLock()
		scheduledRegossip := sb.scheduledAnnounceRegossips[msg.Address]
		// if a regossip for this msg address has been scheduled already, override
		// the scheduling if this version is newer. Otherwise, don't regossip this message
		// and let the scheduled regossip occur.
		if scheduledRegossip != nil {
			if announceVersion > scheduledRegossip.Version {
				sb.scheduledAnnounceRegossipsMu.RUnlock()
				return sb.scheduleAnnounceRegossip(msg, announceVersion, payload)
			}
			sb.scheduledAnnounceRegossipsMu.RUnlock()
			logger.Debug("Announce message is not greater than scheduled regossip version, not regossiping")
			return nil
		}
		sb.scheduledAnnounceRegossipsMu.RUnlock()

		sb.lastAnnounceGossipedMu.RLock()
		if lastGossiped, ok := sb.lastAnnounceGossiped[msg.Address]; ok {
			if time.Since(lastGossiped.Time) < announceGossipCooldownDuration {
				// If this version is newer than the previously regossiped one,
				// schedule it to be regossiped once the cooldown period is over
				if lastGossiped.Version < announceVersion {
					sb.lastAnnounceGossipedMu.RUnlock()
					logger.Trace("Already regossiped msg from this source address with an older announce version within the cooldown period, scheduling regossip for after the cooldown")
					return sb.scheduleAnnounceRegossip(msg, announceVersion, payload)
				}
				sb.lastAnnounceGossipedMu.RUnlock()
				logger.Trace("Already regossiped msg from this source address within the cooldown period, not regossiping.")
				return nil
			}
		}
		sb.lastAnnounceGossipedMu.RUnlock()
	}

	logger.Trace("Regossiping the istanbul announce message", "IstanbulMsg", msg.String())
	if err := sb.Multicast(nil, payload, istanbulAnnounceMsg); err != nil {
		return err
	}

	sb.lastAnnounceGossiped[msg.Address] = &announceRegossip{
		Time:    time.Now(),
		Version: announceVersion,
	}

	return nil
}

// signedAnnounceVersion is a signed message from a validator indicating the most
// recent version of its enode.
type signedAnnounceVersion struct {
	Address   common.Address
	Version   uint
	Signature []byte
}

func newSignedAnnounceVersionFromEntry(entry *vet.SignedAnnounceVersionEntry) *signedAnnounceVersion {
	return &signedAnnounceVersion{
		Address:   entry.Address,
		Version:   entry.Version,
		Signature: entry.Signature,
	}
}

func (sav *signedAnnounceVersion) Sign(signingFn func(data []byte) ([]byte, error)) error {
	payloadNoSig, err := sav.payloadNoSig()
	if err != nil {
		return err
	}
	sav.Signature, err = signingFn(payloadNoSig)
	if err != nil {
		return err
	}
	return nil
}

func (sav *signedAnnounceVersion) ECDSAPublicKey() (*ecdsa.PublicKey, error) {
	payloadNoSig, err := sav.payloadNoSig()
	if err != nil {
		return nil, err
	}
	payloadHash := crypto.Keccak256(payloadNoSig)
	pubkey, err := crypto.SigToPub(payloadHash, sav.Signature)
	if err != nil {
		return nil, err
	}
	return pubkey, nil
}

// ValidateSignature will return an error if a SignedAnnounceVersion's signature
// is invalid.
func (sav *signedAnnounceVersion) ValidateSignature() error {
	payloadNoSig, err := sav.payloadNoSig()
	if err != nil {
		return err
	}
	address, err := istanbul.GetSignatureAddress(payloadNoSig, sav.Signature)
	if err != nil {
		return err
	}
	if address != sav.Address {
		return errors.New("Signature does not match address")
	}
	return nil
}

// EncodeRLP serializes signedAnnounceVersion into the Ethereum RLP format.
func (sav *signedAnnounceVersion) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, []interface{}{sav.Address, sav.Version, sav.Signature})
}

// DecodeRLP implements rlp.Decoder, and load the signedAnnounceVersion fields from a RLP stream.
func (sav *signedAnnounceVersion) DecodeRLP(s *rlp.Stream) error {
	var msg struct {
		Address   common.Address
		Version   uint
		Signature []byte
	}

	if err := s.Decode(&msg); err != nil {
		return err
	}
	sav.Address, sav.Version, sav.Signature = msg.Address, msg.Version, msg.Signature
	return nil
}

func (sav *signedAnnounceVersion) Entry() *vet.SignedAnnounceVersionEntry {
	return &vet.SignedAnnounceVersionEntry{
		Address:   sav.Address,
		Version:   sav.Version,
		Signature: sav.Signature,
	}
}

func (sav *signedAnnounceVersion) payloadNoSig() ([]byte, error) {
	savNoSig := &signedAnnounceVersion{
		Address: sav.Address,
		Version: sav.Version,
	}
	payloadNoSig, err := rlp.EncodeToBytes(savNoSig)
	if err != nil {
		return nil, err
	}
	return payloadNoSig, nil
}

func (sb *Backend) generateSignedAnnounceVersion(version uint) (*signedAnnounceVersion, error) {
	sav := &signedAnnounceVersion{
		Address: sb.Address(),
		Version: version,
	}
	err := sav.Sign(sb.Sign)
	if err != nil {
		return nil, err
	}
	return sav, nil
}

func (sb *Backend) gossipSignedAnnounceVersionsMsg(signedAnnVersions []*signedAnnounceVersion) error {
	logger := sb.logger.New("func", "gossipSignedAnnounceVersionsMsg")

	payload, err := rlp.EncodeToBytes(signedAnnVersions)
	if err != nil {
		logger.Warn("Error encoding entries", "err", err)
		return err
	}
	return sb.Multicast(nil, payload, istanbulSignedAnnounceVersionsMsg)
}

func (sb *Backend) getAllSignedAnnounceVersions() ([]*signedAnnounceVersion, error) {
	allEntries, err := sb.signedAnnounceVersionTable.GetAll()
	if err != nil {
		return nil, err
	}
	allSignedAnnounceVersions := make([]*signedAnnounceVersion, len(allEntries))
	for i, entry := range allEntries {
		allSignedAnnounceVersions[i] = newSignedAnnounceVersionFromEntry(entry)
	}
	return allSignedAnnounceVersions, nil
}

// sendAnnounceVersionTable sends all SignedAnnounceVersions this node
// has to a peer
func (sb *Backend) sendAnnounceVersionTable(peer consensus.Peer) error {
	logger := sb.logger.New("func", "sendAnnounceVersionTable")
	allSignedAnnounceVersions, err := sb.getAllSignedAnnounceVersions()
	if err != nil {
		logger.Warn("Error getting all signed announce versions", "err", err)
		return err
	}
	payload, err := rlp.EncodeToBytes(allSignedAnnounceVersions)
	if err != nil {
		logger.Warn("Error encoding entries", "err", err)
		return err
	}
	return peer.Send(istanbulSignedAnnounceVersionsMsg, payload)
}

func (sb *Backend) handleSignedAnnounceVersionsMsg(peer consensus.Peer, payload []byte) error {
	logger := sb.logger.New("func", "handleSignedAnnounceVersionsMsg")
	logger.Trace("Handling signed announce version msg")
	var signedAnnVersions []*signedAnnounceVersion

	err := rlp.DecodeBytes(payload, &signedAnnVersions)
	if err != nil {
		logger.Warn("Error in decoding received Signed Announce Versions msg", "err", err)
		return err
	}

	// If the announce's valAddress is not within the validator connection set, then ignore it
	validatorConnSet, err := sb.retrieveValidatorConnSet()
	if err != nil {
		logger.Trace("Error in retrieving validator conn set", "err", err)
		return err
	}

	var validEntries []*vet.SignedAnnounceVersionEntry
	validAddresses := make(map[common.Address]bool)
	// Verify all entries are valid and remove duplicates
	for _, signedAnnVersion := range signedAnnVersions {
		err := signedAnnVersion.ValidateSignature()
		if err != nil {
			logger.Debug("Error validating signed announce version signature", "address", signedAnnVersion.Address, "err", err)
			continue
		}
		if !validatorConnSet[signedAnnVersion.Address] {
			logger.Debug("Found signed announce version from an address not in the validator conn set", "address", signedAnnVersion.Address)
			continue
		}
		if _, ok := validAddresses[signedAnnVersion.Address]; ok {
			logger.Debug("Found duplicate signed announce version in message", "address", signedAnnVersion.Address)
			continue
		}
		validAddresses[signedAnnVersion.Address] = true
		validEntries = append(validEntries, signedAnnVersion.Entry())
	}
	if err := sb.upsertAndGossipSignedAnnounceVersionEntries(validEntries); err != nil {
		logger.Warn("Error upserting and gossiping entries", "err", err)
		return err
	}
	return nil
}

func (sb *Backend) upsertAndGossipSignedAnnounceVersionEntries(entries []*vet.SignedAnnounceVersionEntry) error {
	logger := sb.logger.New("func", "upsertSignedAnnounceVersions")
	newEntries, err := sb.signedAnnounceVersionTable.Upsert(entries)
	if err != nil {
		logger.Warn("Error in upserting entries", "err", err)
	}

	// Only regossip entries that do not originate from an address that we have
	// gossiped a signed announce version for within the last 5 minutes, excluding
	// our own address.
	var signedAnnVersionsToRegossip []*signedAnnounceVersion
	sb.lastSignedAnnounceVersionsGossipedMu.Lock()
	for _, entry := range newEntries {
		lastGossipTime, ok := sb.lastSignedAnnounceVersionsGossiped[entry.Address]
		if ok && time.Since(lastGossipTime) >= signedAnnounceVersionGossipCooldownDuration && entry.Address != sb.ValidatorAddress() {
			continue
		}
		signedAnnVersionsToRegossip = append(signedAnnVersionsToRegossip, &signedAnnounceVersion{
			Address:   entry.Address,
			Version:   entry.Version,
			Signature: entry.Signature,
		})
		sb.lastSignedAnnounceVersionsGossiped[entry.Address] = time.Now()
	}
	sb.lastSignedAnnounceVersionsGossipedMu.Unlock()
	if len(signedAnnVersionsToRegossip) > 0 {
		return sb.gossipSignedAnnounceVersionsMsg(signedAnnVersionsToRegossip)
	}
	return nil
}

// updateAnnounceVersion will synchronously update the announce version.
// Must be called in a separate goroutine from the announceThread to avoid
// a deadlock.
func (sb *Backend) updateAnnounceVersion() {
	sb.updateAnnounceVersionCh <- struct{}{}
	<-sb.updateAnnounceVersionCompleteCh
}

// setAndShareUpdatedAnnounceVersion generates announce data structures and
// and shares them with relevant nodes.
// It will:
//  1) Generate a new enode certificate
//  2) Send the new enode certificate to this node's proxy if one exists
//  3) Send the new enode certificate to all peers in the validator conn set
//  4) Generate a new signed announce version
//  5) Gossip the new signed announce version to all peers
func (sb *Backend) setAndShareUpdatedAnnounceVersion(version uint) error {
	logger := sb.logger.New("func", "setAndShareUpdatedAnnounceVersion")
	// Send new versioned enode msg to all other registered or elected validators
	validatorConnSet, err := sb.retrieveValidatorConnSet()
	if err != nil {
		return err
	}
	enodeCertificateMsg, err := sb.generateEnodeCertificateMsg(version)
	if err != nil {
		return err
	}
	sb.setEnodeCertificateMsg(enodeCertificateMsg)
	// Send the new versioned enode msg to the proxy peer
	if sb.config.Proxied && sb.proxyNode != nil && sb.proxyNode.peer != nil {
		err := sb.sendEnodeCertificateMsg(sb.proxyNode.peer, enodeCertificateMsg)
		if err != nil {
			logger.Error("Error in sending versioned enode msg to proxy", "err", err)
			return err
		}
	}
	// Don't send any of the following messages if this node is not in the validator conn set
	if !validatorConnSet[sb.Address()] {
		logger.Trace("Not in the validator conn set, not updating announce version")
		return nil
	}
	payload, err := enodeCertificateMsg.Payload()
	if err != nil {
		return err
	}
	destAddresses := make([]common.Address, len(validatorConnSet))
	i := 0
	for address := range validatorConnSet {
		destAddresses[i] = address
		i++
	}
	err = sb.Multicast(destAddresses, payload, istanbulEnodeCertificateMsg)
	if err != nil {
		return err
	}

	// Generate and gossip a new signed announce version
	newSignedAnnVersion, err := sb.generateSignedAnnounceVersion(version)
	if err != nil {
		return err
	}
	return sb.upsertAndGossipSignedAnnounceVersionEntries([]*vet.SignedAnnounceVersionEntry{
		newSignedAnnVersion.Entry(),
	})
}

func (sb *Backend) getEnodeURL() (string, error) {
	if sb.config.Proxied {
		if sb.proxyNode != nil {
			return sb.proxyNode.externalNode.URLv4(), nil
		}
		return "", errNoProxyConnection
	}
	return sb.p2pserver.Self().URLv4(), nil
}

func newAnnounceVersion() uint {
	// Unix() returns a int64, but we need a uint for the golang rlp encoding implmentation. Warning: This timestamp value will be truncated in 2106.
	return uint(time.Now().Unix())
}

type enodeCertificate struct {
	EnodeURL string
	Version  uint
}

// ==============================================
//
// define the functions that needs to be provided for rlp Encoder/Decoder.

// EncodeRLP serializes ec into the Ethereum RLP format.
func (ec *enodeCertificate) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, []interface{}{ec.EnodeURL, ec.Version})
}

// DecodeRLP implements rlp.Decoder, and load the ec fields from a RLP stream.
func (ec *enodeCertificate) DecodeRLP(s *rlp.Stream) error {
	var msg struct {
		EnodeURL string
		Version  uint
	}

	if err := s.Decode(&msg); err != nil {
		return err
	}
	ec.EnodeURL, ec.Version = msg.EnodeURL, msg.Version
	return nil
}

// retrieveEnodeCertificateMsg gets the most recent enode certificate message.
// May be nil if no message was generated as a result of the core not being
// started, or if a proxy has not received a message from its proxied validator
func (sb *Backend) retrieveEnodeCertificateMsg() (*istanbul.Message, error) {
	sb.enodeCertificateMsgMu.Lock()
	defer sb.enodeCertificateMsgMu.Unlock()
	if sb.enodeCertificateMsg == nil {
		return nil, nil
	}
	return sb.enodeCertificateMsg.Copy(), nil
}

// generateEnodeCertificateMsg generates an enode certificate message with the enode
// this node is publicly accessible at. If this node is proxied, the proxy's
// public enode is used.
func (sb *Backend) generateEnodeCertificateMsg(version uint) (*istanbul.Message, error) {
	logger := sb.logger.New("func", "generateEnodeCertificateMsg")

	var enodeURL string
	if sb.config.Proxied {
		if sb.proxyNode != nil {
			enodeURL = sb.proxyNode.externalNode.URLv4()
		} else {
			return nil, errNoProxyConnection
		}
	} else {
		enodeURL = sb.p2pserver.Self().URLv4()
	}

	enodeCertificate := &enodeCertificate{
		EnodeURL: enodeURL,
		Version:  version,
	}
	enodeCertificateBytes, err := rlp.EncodeToBytes(enodeCertificate)
	if err != nil {
		return nil, err
	}
	msg := &istanbul.Message{
		Code:    istanbulEnodeCertificateMsg,
		Address: sb.Address(),
		Msg:     enodeCertificateBytes,
	}
	// Sign the message
	if err := msg.Sign(sb.Sign); err != nil {
		return nil, err
	}
	logger.Trace("Generated Istanbul Enode Certificate message", "enodeCertificate", enodeCertificate, "address", msg.Address)
	return msg, nil
}

// handleEnodeCertificateMsg handles an enode certificate message.
// If this node is a proxy and the enode certificate is from a remote validator
// (ie not the proxied validator), this node will forward the enode certificate
// to its proxied validator. If the proxied validator decides this node should process
// the enode certificate and upsert it into its val enode table, the proxied validator
// will send it back to this node.
// If the proxied validator sends an enode certificate for itself to this node,
// this node will set the enode certificate as its own for handshaking.
func (sb *Backend) handleEnodeCertificateMsg(peer consensus.Peer, payload []byte) error {
	logger := sb.logger.New("func", "handleEnodeCertificateMsg")

	var msg istanbul.Message
	// Decode payload into msg
	err := msg.FromPayload(payload, istanbul.GetSignatureAddress)
	if err != nil {
		logger.Error("Error in decoding received Istanbul Enode Certificate message", "err", err, "payload", hex.EncodeToString(payload))
		return err
	}
	logger = logger.New("msg address", msg.Address)

	var enodeCertificate enodeCertificate
	if err := rlp.DecodeBytes(msg.Msg, &enodeCertificate); err != nil {
		logger.Warn("Error in decoding received Istanbul Enode Certificate message content", "err", err, "IstanbulMsg", msg.String())
		return err
	}
	logger.Trace("Received Istanbul Enode Certificate message", "enodeCertificate", enodeCertificate)

	parsedNode, err := enode.ParseV4(enodeCertificate.EnodeURL)
	if err != nil {
		logger.Warn("Malformed v4 node in received Istanbul Enode Certificate message", "enodeCertificate", enodeCertificate, "err", err)
		return err
	}

	if sb.config.Proxy && sb.proxiedPeer != nil {
		if sb.proxiedPeer.Node().ID() == peer.Node().ID() {
			// if this message is from the proxied peer and contains the proxied
			// validator's enodeCertificate, save it for handshake use
			if msg.Address == sb.config.ProxiedValidatorAddress {
				existingVersion := sb.getEnodeCertificateMsgVersion()
				if enodeCertificate.Version < existingVersion {
					logger.Warn("Enode certificate from proxied peer contains version lower than existing enode msg", "msg version", enodeCertificate.Version, "existing", existingVersion)
					return errors.New("Version too low")
				}
				// There may be a difference in the URLv4 string because of `discport`,
				// so instead compare the ID
				selfNode := sb.p2pserver.Self()
				if parsedNode.ID() != selfNode.ID() {
					logger.Warn("Received Istanbul Enode Certificate message with an incorrect enode url", "message enode url", enodeCertificate.EnodeURL, "self enode url", sb.p2pserver.Self().URLv4())
					return errors.New("Incorrect enode url")
				}
				if err := sb.setEnodeCertificateMsg(&msg); err != nil {
					logger.Warn("Error setting enode certificate msg", "err", err)
					return err
				}
				return nil
			}
		} else {
			// If this message is not from the proxied validator, send it to the
			// proxied validator without upserting it in this node. If the validator
			// decides this proxy should upsert the enodeCertificate, then it
			// will send it back to this node.
			if err := sb.sendEnodeCertificateMsg(sb.proxiedPeer, &msg); err != nil {
				logger.Warn("Error forwarding enodeCertificate to proxied validator", "err", err)
			}
			return nil
		}
	}

	validatorConnSet, err := sb.retrieveValidatorConnSet()
	if err != nil {
		logger.Debug("Error in retrieving registered/elected valset", "err", err)
		return err
	}

	if !validatorConnSet[msg.Address] {
		logger.Debug("Received Istanbul Enode Certificate message originating from a node not in the validator conn set")
		return errUnauthorizedAnnounceMessage
	}

	if err := sb.valEnodeTable.Upsert(map[common.Address]*vet.AddressEntry{msg.Address: {Node: parsedNode, Version: enodeCertificate.Version}}); err != nil {
		logger.Warn("Error in upserting a val enode table entry", "error", err)
		return err
	}
	return nil
}

func (sb *Backend) sendEnodeCertificateMsg(peer consensus.Peer, msg *istanbul.Message) error {
	logger := sb.logger.New("func", "sendEnodeCertificateMsg")
	payload, err := msg.Payload()
	if err != nil {
		logger.Error("Error getting payload of enode certificate message", "err", err)
		return err
	}
	return peer.Send(istanbulEnodeCertificateMsg, payload)
}

func (sb *Backend) setEnodeCertificateMsg(msg *istanbul.Message) error {
	sb.enodeCertificateMsgMu.Lock()
	var enodeCertificate enodeCertificate
	if err := rlp.DecodeBytes(msg.Msg, &enodeCertificate); err != nil {
		return err
	}
	sb.enodeCertificateMsg = msg
	sb.enodeCertificateMsgVersion = enodeCertificate.Version
	sb.enodeCertificateMsgMu.Unlock()
	return nil
}

func (sb *Backend) getEnodeCertificateMsgVersion() uint {
	sb.enodeCertificateMsgMu.RLock()
	defer sb.enodeCertificateMsgMu.RUnlock()
	return sb.enodeCertificateMsgVersion
}
