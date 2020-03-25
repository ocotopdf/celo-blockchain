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

package enodes

import (
       "bytes"
       "crypto/ecdsa"
       "encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/syndtr/goleveldb/leveldb"
	lvlerrors "github.com/syndtr/goleveldb/leveldb/errors"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/storage"
	"github.com/syndtr/goleveldb/leveldb/util"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/rlp"
)

// Keys in the node database.
const (
      dbVersionKey    = "version"  // Version of the database to flush if changes
      dbAddressPrefix = "address:" // Identifier to prefix node entries with
      dbNodeIDPrefix  = "nodeid:"
)

const (
      // dbNodeExpiration = 24 * time.Hour // Time after which an unseen node should be dropped.
      // dbCleanupCycle   = time.Hour      // Time period for running the expiration task.
      dbVersion = 3
)

// ValidatorEnodeHandler is handler to Add/Remove events. Events execute within write lock
type ValidatorEnodeHandler interface {
	// AddValidatorPeer adds a validator peer
	AddValidatorPeer(node *enode.Node, address common.Address)

	// RemoveValidatorPeer removes a validator peer
	RemoveValidatorPeer(node *enode.Node)

	// ReplaceValidatorPeers replace all validator peers for new list of enodeURLs
	ReplaceValidatorPeers(newNodes []*enode.Node)

	// Clear all validator peers
	ClearValidatorPeers()
}

func nodeIDKey(nodeID enode.ID) []byte {
	return append([]byte(dbNodeIDPrefix), nodeID.Bytes()...)
}

func addressKey(address common.Address) []byte {
	return append([]byte(dbAddressPrefix), address.Bytes()...)
}

// newMemoryDB creates a new in-memory node database without a persistent backend.
func newMemoryDB() (*leveldb.DB, error) {
	db, err := leveldb.Open(storage.NewMemStorage(), nil)
	if err != nil {
		return nil, err
	}
	return db, nil
}

// newPersistentNodeDB creates/opens a leveldb backed persistent database,
// also flushing its contents in case of a version mismatch.
func newPersistentDB(dbVersion int64, path string, logger log.Logger) (*leveldb.DB, error) {
	opts := &opt.Options{OpenFilesCacheCapacity: 5}
	db, err := leveldb.OpenFile(path, opts)
	if _, iscorrupted := err.(*lvlerrors.ErrCorrupted); iscorrupted {
		db, err = leveldb.RecoverFile(path, nil)
	}
	if err != nil {
		return nil, err
	}
	currentVer := make([]byte, binary.MaxVarintLen64)
	currentVer = currentVer[:binary.PutVarint(currentVer, dbVersion)]

	blob, err := db.Get([]byte(dbVersionKey), nil)
	switch err {
	case leveldb.ErrNotFound:
		// Version not found (i.e. empty cache), insert it
		if err := db.Put([]byte(dbVersionKey), currentVer, nil); err != nil {
			db.Close()
			return nil, err
		}

	case nil:
		// Version present, flush if different
		if !bytes.Equal(blob, currentVer) {
			oldVersion, _ := binary.Varint(blob)
			newVersion, _ := binary.Varint(currentVer)
			logger.Info("DB version has changed. Creating a new leveldb.", "old version", oldVersion, "new version", newVersion)
			db.Close()
			if err = os.RemoveAll(path); err != nil {
				return nil, err
			}
			return newPersistentDB(dbVersion, path, logger)
		}
	}
	return db, nil
}

// AddressEntry is an entry for the valEnodeTable
type AddressEntry struct {
        PublicKey  *ecdsa.PublicKey
	Node    *enode.Node
	Version uint
	HighestKnownVersion uint
	NumQueryAttemptsForTimestamp int
	TimestampOfLastQuery int64   // timestamp in unix time format
}

func (ve *AddressEntry) String() string {
	return fmt.Sprintf("{enodeURL: %v, version: %v, highestKnownVersion: %d, numRetries: %d, lastRetry: %d}",
	                   ve.Node.String(), ve.Version. ve.HighestKnownVersion, ve.NumRetries, ve.LastRetryTimestamp)
}

// Implement RLP Encode/Decode interface
type rlpEntry struct {
        CompressedPublicKey []byte
	EnodeURL string
	Version  uint
	HighestKnownVersion uint
	NumRetries int
	LastRetryTimestamp int64
}

// EncodeRLP serializes AddressEntry into the Ethereum RLP format.
func (ve *AddressEntry) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, rlpEntry{crypto.CompressPubkey(ve.PublicKey), ve.Node.String(), ve.Version, ve.NumRetries, ve.LastRetryTimestamp})
}


// DecodeRLP implements rlp.Decoder, and load the AddressEntry fields from a RLP stream.
func (ve *AddressEntry) DecodeRLP(s *rlp.Stream) error {
	var entry rlpEntry
	if err := s.Decode(&entry); err != nil {
		return err
	}

	node, err := enode.ParseV4(entry.EnodeURL)
	if err != nil {
		return err
	}

	publicKey, err := crypto.DecompressPubkey(entry.CompressedPublicKey)
	if err != nil {
	        return err
	}

	*ve = AddressEntry{PublicKey: publicKey, Node: node, Version: entry.Version, entry.NumRetries, ve.LastRetryTimestamp}
	return nil
}

// ValidatorEnodeDB represents a Map that can be accessed either
// by address or enode
type ValidatorEnodeDB struct {
	db      *leveldb.DB //the actual DB
	lock    sync.RWMutex
	handler ValidatorEnodeHandler
	logger  log.Logger
}

// OpenValidatorEnodeDB opens a validator enode database for storing and retrieving infos about validator
// enodes. If no path is given an in-memory, temporary database is constructed.
func OpenValidatorEnodeDB(path string, handler ValidatorEnodeHandler) (*ValidatorEnodeDB, error) {
	var db *leveldb.DB
	var err error

	logger := log.New("db", "ValidatorEnodeDB")

	if path == "" {
		db, err = newMemoryDB()
	} else {
		db, err = newPersistentDB(int64(valEnodeDBVersion), path, logger)
	}

	if err != nil {
		return nil, err
	}
	return &ValidatorEnodeDB{
		db:      db,
		handler: handler,
		logger:  logger,
	}, nil
}

// Close flushes and closes the database files.
func (vet *ValidatorEnodeDB) Close() error {
	return vet.db.Close()
}

func (vet *ValidatorEnodeDB) String() string {
	vet.lock.RLock()
	defer vet.lock.RUnlock()
	var b strings.Builder
	b.WriteString("ValEnodeTable:")

	err := vet.iterateOverAddressEntries(func(address common.Address, entry *AddressEntry) error {
		fmt.Fprintf(&b, " [%s => %s]", address.String(), entry.String())
		return nil
	})

	if err != nil {
		vet.logger.Error("ValidatorEnodeDB.String error", "err", err)
	}

	return b.String()
}

// GetEnodeURLFromAddress will return the enodeURL for an address if it's known
func (vet *ValidatorEnodeDB) GetNodeFromAddress(address common.Address) (*enode.Node, error) {
	vet.lock.RLock()
	defer vet.lock.RUnlock()
	entry, err := vet.getAddressEntry(address)
	if err != nil {
		return nil, err
	}
	return entry.Node, nil
}

// GetVersionFromAddress will return the version for an address if it's known
func (vet *ValidatorEnodeDB) GetVersionFromAddress(address common.Address) (uint, error) {
	vet.lock.RLock()
	defer vet.lock.RUnlock()
	entry, err := vet.getAddressEntry(address)
	if err != nil {
		return 0, err
	}
	return entry.Version, nil
}

// GetAddressFromNodeID will return the address for an nodeID if it's known
func (vet *ValidatorEnodeDB) GetAddressFromNodeID(nodeID enode.ID) (common.Address, error) {
	vet.lock.RLock()
	defer vet.lock.RUnlock()

	rawEntry, err := vet.db.Get(nodeIDKey(nodeID), nil)
	if err != nil {
		return common.ZeroAddress, err
	}
	return common.BytesToAddress(rawEntry), nil
}

// GetHighestKnownVersion will return the highest known version for an address if it's known
func (vet *ValidatorEnodeDB) GetHighestKnownVersionFromAddress(address common.Address) (uint, error) {
        vet.lock.RLock()
	defer vet.lock.RUnlock()
	
	entry, err := vet.getAddressEntry(address)
	if err != nil {
		return 0, err
	}
	return entry.HighestKnownVersion, nil
}

// GetAllValEnodes will return all entries in the valEnodeDB
func (vet *ValidatorEnodeDB) GetAllValEnodes() (map[common.Address]*AddressEntry, error) {
	vet.lock.RLock()
	defer vet.lock.RUnlock()
	var entries = make(map[common.Address]*AddressEntry)

	err := vet.iterateOverAddressEntries(func(address common.Address, entry *AddressEntry) error {
		entries[address] = entry
		return nil
	})

	if err != nil {
		vet.logger.Error("ValidatorEnodeDB.GetAllAddressEntries error", "err", err)
		return nil, err
	}

	return entries, nil
}

// Upsert will update or insert a validator enode entry; given that the existing entry
// is older (determined by version parameter) than the new one
// TODO - In addition to modifying the val_enode_db, this function also will disconnect
//        and/or connect the corresponding validator connenctions.  The validator connections
//        should be managed be a separate thread (see https://github.com/celo-org/celo-blockchain/issues/607)
func (vet *ValidatorEnodeDB) Upsert(valEnodeEntries map[common.Address]*AddressEntry, onlyHighestKnownVersionUpdated bool) error {
	vet.lock.Lock()
	defer vet.lock.Unlock()

	batch := new(leveldb.Batch)
	peersToRemove := make([]*enode.Node, 0, len(valEnodeEntries))
	peersToAdd := make(map[common.Address]*enode.Node)

	for remoteAddress, addressEntry := range valEnodeEntries {
		currentEntry, err := vet.getAddressEntry(remoteAddress)
		isNew := err == leveldb.ErrNotFound

		// Check errors
		if !isNew && err != nil {
			return err
		}

		// If it's an old message, ignore it
		if !isNew {
		        if onlyHighestKnownVersionUpdate {
			   if addressEntry.HighestKnownVersion < currentEntry.HighestKnownVersion {
			     vet.logger.Trace("Ignoring the entry because its highestKnownVersion is lower than what is stored in the val enode db",
				"entryAddress", remoteAddress, "newEntry", addressEntry.String(), "currentEntry", currentEntry.String())
			     continue
			   }
			} else {
			  if addressEntry.Version <= currentEntry.Version {
			     vet.logger.Trace("Ignorning the entry because its version is lower than what is stored in the val enode db",
				"entryAddress", remoteAddress, "newEntry", addressEntry.String(), "currentEntry", currentEntry.String())
			     continue			     
			  }
			}
		}

		enodeURLChanged := false
		if !isNew && !onlyHighestKnownVersionUpdate && addressEntry.Version > currentEntry.Version && addressEntry.enodeURL != currentEntry.enodeURL {
		   enodeURLChanged = true
		}

		// Construct the new addressEntry to save into the level db
		var entryToSave AddressEntry

		// First save the original values from currentEntry
		if !isNew {
		   entryToSave = currentEntry
		}
		
		if onlyHighestKnownVersionUpdate {
		   entryToSave.HighestKnownVersionToSave = addressEntry.HighestKnownVersionToSave
		   // Reset the retries counter
		   entryToSave.NumQueryAttemptsForTimestamp = 0
		} else {
		   entryToSave.EnodeURL = addressEntry.EnodeURL
		   entryToSave.Version = addressEntry.Version

		   // Set the HighestKnownVersion if it's lower than Version or this is a new entry
		   if isNew || (addressEntry.Version >= entryToSave.HighestKnownVersionToSave) {
		      entryToSave.HighestKnownVersionToSave = addressEntry.Version
		      entryToSave.NumQueryAttemptsForTimestamp = 0
		   }
		}

		// The public key is always passed in
		entryToSave.PublicKey = addressEntry.PublicKey

		rawEntry, err := rlp.EncodeToBytes(entryToSave)
		if err != nil {
			return err
		}		

		if enodeURLChanged {
			batch.Delete(nodeIDKey(currentEntry.Node.ID()))
			batch.Put(nodeIDKey(entryToSave.Node.ID()), remoteAddress.Bytes())
			peersToRemove = append(peersToRemove, currentEntry.Node)
		} else if isNew {
			batch.Put(nodeIDKey(entryToSave.Node.ID()), remoteAddress.Bytes())
		}
		batch.Put(addressKey(remoteAddress), rawEntry)
		peersToAdd[remoteAddress] = entryToSave.Node

		vet.logger.Trace("Going to upsert an entry in the valEnodeTable", "address", remoteAddress, "enodeURL", addressEntry.Node.String())
	}

	if batch.Len() > 0 {
		err := vet.db.Write(batch, nil)
		if err != nil {
			return err
		} else {
			for _, node := range peersToRemove {
				vet.handler.RemoveValidatorPeer(node)
			}

			for address, node := range peersToAdd {
				vet.handler.AddValidatorPeer(node, address)
			}
		}
	}

	return nil
}

func (vet *ValidatorEnodeDB) UpdateQueryEnodeStats(valAddresses []common.Address) error {
     vet.lock.Lock()
     defer vet.lock.Unlock()

     batch := new(leveldb.Batch)
     for valAddress := range valAddresses {
         currentEntry, err := vet.getAddressEntry(valAddress)

	 if err != nil {
	    return err
	 }

	 currentEntry.NumQueryAttemptsForTimestamp += 1
	 currentEntry.TimestampOfLastQuery = time.Unix()

	 rawEntry, err := rlp.EncodeToBytes(currentEntry)
	 if err != nil {
		return err
	 }

	 batch.Put(addressKey(remoteAddress), rawEntry)
     }

     if batch.Len() > 0 {
     	err := vet.db.Write(batch, nil)
	if err != nil {
	   return err
	}
     }

     return nil
}

// RemoveEntry will remove an entry from the table
func (vet *ValidatorEnodeDB) RemoveEntry(address common.Address) error {
	vet.lock.Lock()
	defer vet.lock.Unlock()
	batch := new(leveldb.Batch)
	err := vet.addDeleteToBatch(batch, address)
	if err != nil {
		return err
	}
	return vet.db.Write(batch, nil)
}

// PruneEntries will remove entries for all address not present in addressesToKeep
func (vet *ValidatorEnodeDB) PruneEntries(addressesToKeep map[common.Address]bool) error {
	vet.lock.Lock()
	defer vet.lock.Unlock()
	batch := new(leveldb.Batch)
	err := vet.iterateOverAddressEntries(func(address common.Address, entry *AddressEntry) error {
		if !addressesToKeep[address] {
			vet.logger.Trace("Deleting entry from valEnodeTable", "address", address)
			return vet.addDeleteToBatch(batch, address)
		}
		return nil
	})

	if err != nil {
		return err
	}
	return vet.db.Write(batch, nil)
}

func (vet *ValidatorEnodeDB) RefreshValPeers(valConnSet map[common.Address]bool, ourAddress common.Address) {
	// We use a R lock since we don't modify levelDB table
	vet.lock.RLock()
	defer vet.lock.RUnlock()

	if valConnSet[ourAddress] {
		// transform address to enodeURLs
		newNodes := []*enode.Node{}
		for val := range valConnSet {
			entry, err := vet.getAddressEntry(val)
			if err == nil {
				newNodes = append(newNodes, entry.Node)
			} else if err != leveldb.ErrNotFound {
				vet.logger.Error("Error reading valEnodeTable: GetEnodeURLFromAddress", "err", err)
			}
		}

		vet.handler.ReplaceValidatorPeers(newNodes)
	} else {
		// Disconnect all validator peers if this node is not in the valset
		vet.handler.ClearValidatorPeers()
	}
}

func (vet *ValidatorEnodeDB) addDeleteToBatch(batch *leveldb.Batch, address common.Address) error {
	entry, err := vet.getAddressEntry(address)
	if err != nil {
		return err
	}

	batch.Delete(addressKey(address))
	batch.Delete(nodeIDKey(entry.Node.ID()))
	if vet.handler != nil {
		vet.handler.RemoveValidatorPeer(entry.Node)
	}
	return nil
}

func (vet *ValidatorEnodeDB) getAddressEntry(address common.Address) (*AddressEntry, error) {
	var entry AddressEntry
	rawEntry, err := vet.db.Get(addressKey(address), nil)
	if err != nil {
		return nil, err
	}

	if err = rlp.DecodeBytes(rawEntry, &entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

func (vet *ValidatorEnodeDB) iterateOverAddressEntries(onEntry func(common.Address, *AddressEntry) error) error {
	iter := vet.db.NewIterator(util.BytesPrefix([]byte(dbAddressPrefix)), nil)
	defer iter.Release()

	for iter.Next() {
		var entry AddressEntry
		address := common.BytesToAddress(iter.Key()[len(dbAddressPrefix):])
		rlp.DecodeBytes(iter.Value(), &entry)

		err := onEntry(address, &entry)
		if err != nil {
			return err
		}
	}
	return iter.Error()
}

// ValEnodeEntryInfo contains information for an entry of the val enode table
type ValEnodeEntryInfo struct {
	Enode   string `json:"enode"`
	Version uint   `json:"version"`
}

// ValEnodeTableInfo gives basic information for each entry of the table
func (vet *ValidatorEnodeDB) ValEnodeTableInfo() (map[string]*ValEnodeEntryInfo, error) {
	valEnodeTableInfo := make(map[string]*ValEnodeEntryInfo)

	valEnodeTable, err := vet.GetAllValEnodes()
	if err == nil {
		for address, valEnodeEntry := range valEnodeTable {
			valEnodeTableInfo[address.Hex()] = &ValEnodeEntryInfo{
				Enode:   valEnodeEntry.Node.String(),
				Version: valEnodeEntry.Version,
			}
		}
	}

	return valEnodeTableInfo, err
}
