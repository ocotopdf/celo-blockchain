
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

type encryptedEnodeURL struct {
	DestAddress       common.Address    // Validator address that this entry is intended for.
	EncryptedEnodeURL      []byte       // Encrypted enodeURL requester.  Can be decrypted by the DestAddress'es public key 
}

// String returns a string representation of ee
func (ee *encryptedEnodeURL) String() string {
	return fmt.Sprintf("{DecryptorAddress: %s, EncryptedEnodeURL length: %d}", ee.DecryptorAddress.String(), len(ee.EncryptedEnodeURL))
}

// EncodeRLP serializes ee into the Ethereum RLP format.
func (ee *encryptedEnodeURL) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, []interface{}{ee.DestAddress, ee.EncryptedEnodeURL})
}

// DecodeRLP implements rlp.Decoder, and load the ee fields from a RLP stream.
func (ee *encryptedEnodeURL) DecodeRLP(s *rlp.Stream) error {
	var msg struct {
		DestAddress       common.Address
		EncryptedEnodeURL []byte
	}

	if err := s.Decode(&msg); err != nil {
		return err
	}
	ee.DestAddress, ee.EncryptedEnodeURL = msg.DestAddress, msg.EncryptedEnodeURL
	return nil
}

type queryEnodeData struct {
	EncryptedEnodeURLs []*encryptedEnodeURL
	Version         uint
}

// String returns a string representation of er
func (eq *queryEnodeData) String() string {
	return fmt.Sprintf("{Version: %v, enodeURLRecords: %v}", eq.Version, eq.enodeURLRecords)
}

// EncodeRLP serializes ad into the Ethereum RLP format.
func (eq *queryEnodeData) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, []interface{}{eq.AnnounceRecords, eq.Version})
}

// DecodeRLP implements rlp.Decoder, and load the ad fields from a RLP stream.
func (eq *queryEnodeData) DecodeRLP(s *rlp.Stream) error {
	var msg struct {
		EncryptedEnodeURLs []*encryptedEnodeURL
		Version         uint
	}

	if err := s.Decode(&msg); err != nil {
		return err
	}
	eq.EncryptedEnodeURLs, eq.Version = msg.EncrypedEnodeURLs, msg.Version
	return nil
}


// generateAndGossipEnodeQuery will generate the a queryEnode msg
// and broadcast it to it's peers, which should then regossip it throughout the
// p2p network.
func (ah *announceHandler) generateAndGossipQueryEnode(version uint, destAddresses []common.Address) (bool, error) {
	logger := sb.logger.New("func", "generateAndGossipQueryEnode")
	logger.Trace("generateAndGossipQueryEnode called")
	msg, destAddresses, err := sb.generateQueryEnode(version)
	if err != nil || msg == nil {
		return false, err
	}

	// Convert to payload
	payload, err := msg.Payload()
	if err != nil {
		logger.Error("Error in converting QueryEnode Message to payload", "QueryEnodeMsg", msg.String(), "err", err)
		return true, err
	}

	if err := sb.Multicast(nil, payload, istanbulQueryEnodeMsg); err != nil {
		return true, err
	}

	// Update the val_enode_db table's last query timestamp and num query attempts
	an.sb.valEnodeTable.UpdateQueryEnodeStats(destAddresses)
	
	return true, nil
}

// generateQueryEnodeMessage returns an queryEnode message from this node with a given version.
func (ah *announceHandler) generateQueryEnodeMessage(version uint) (*istanbul.Message, []common.Address, error) {
	logger := sb.logger.New("func", "generateQueryEnodeMessage")

	enodeURL, err := sb.getEnodeURL()
	if err != nil {
		logger.Error("Error getting enode URL", "err", err)
		return nil, err
	}
	encryptedEnodeURLs, destAddresses, err := sb.generateEncryptedEnodeURLs(enodeURL, destAddresses)
	if err != nil {
		logger.Warn("Error generating encrypted enodeurls", "err", err)
		return nil, err
	}
	if len(encryptedEnodeURLs) == 0 {
		logger.Trace("No encrypted enodeURLs were generated")
		return nil, nil
	}
	queryEnodeData := &queryEnodeData{
		EncryptedEnodeURLs: encryptedEnodeURLs
		Version:         version,
	}

	queryEnodeBytes, err := rlp.EncodeToBytes(queryEnodeData)
	if err != nil {
		logger.Error("Error encoding queryEnode data", "queryEnodeData", queryEnodeData.String(), "err", err)
		return nil, err
	}

	msg := &istanbul.Message{
		Code:      istanbulQueryEnodeMsg,
		Msg:       queryEnodeBytes,
		Address:   sb.Address(),
		Signature: []byte{},
	}

	// Sign the queryEnode message
	if err := msg.Sign(sb.Sign); err != nil {
		logger.Error("Error in signing an QueryEnode Message", "generateQueryEnodeMsg", msg.String(), "err", err)
		return nil, err
	}

	logger.Debug("Generated an QueryEnode message", "IstanbulMsg", msg.String(), "queryEnodeData", queryEnodeData.String())

	return msg, destAddresses, nil
}


// generateEncryptedEnodeURLs returns the encrypted enodeURLs intended for validators
// whose entries in the val enode table do not exist or are outdated when compared
// to the signed announce version table.
func (ah *announceHandler) generateEncryptedEnodeURLs(enodeURL string) ([]*encryptedEnodeURL, []common.Address, error) {
	valEnodeEntries, err := ah.valEnodeTable.GetAllValEnodes()
	if err != nil {
		return nil, err
	}

	encryptedEnodeURLs := make([]*encryptedEnodeURL, 1)
	destAddresses := make([]common.Address, 1)
	for address, valEnodeEntry := range valEnodeEntries {
		// Don't generate an announce record for ourselves
		if address == sb.Address() {
			continue
		}

		if valEnodeEntry.Version == valEnodeEntry.MaxKnownVersion {
		   continue
		}

		// Check to see if a queryEnode msg should be sent for this entry.
		timeoutForQuery := (2 ** valEnodeEntry.NumQueryAttemptsForTimestamp - 1) * time.Duration(5 * time.Minute)

		// Cap the timeout to an hour
		if timeoutForQuery > time.Duration(1 * time.Hour) {
		   timeoutForQuery = time.Duration(1 * time.Hour)
		}

		if valEnodeEntry.TimestampOfLastQuery + timeoutForQuery.Seconds() > time.Unix() {
		   continue
		}

		publicKey := ecies.ImportECDSAPublic(valEnodeEntry.PublicKey)
		encryptedEnodeURL, err := ecies.Encrypt(rand.Reader, publicKey, []byte(enodeURL), nil, nil)
		if err != nil {
			return nil, err
		}
		
		encryptedEnodeURLs = append(encryptedEnodeURLs, &encryptedEnodeURL{
			DestAddress:       address,
			EncryptedEnodeURL: encryptedEnodeURL,
		})

		destAddresses = append(destAddresses, address)
	}
	return encryptedEnodeURLs, destAddresses, nil
}

// This function will handle an queryEnode message.
func (ah *announceHandler) handleQueryEnodeMsg(peer consensus.Peer, payload []byte) error {
	logger := sb.logger.New("func", "handleQueryEnodeMsg")

	msg := new(istanbul.Message)

	// Decode message
	signerPubKey, err := msg.FromPayload(payload, istanbul.GetSignatureAddress)
	if err != nil {
		logger.Error("Error in decoding received Istanbul QueryEnode message", "err", err, "payload", hex.EncodeToString(payload))
		return err
	}
	logger.Trace("Handling an IstanbulQueryEnode message", "from", msg.Address)

	// Check if the sender is within the validator connection set
	ah.announceValSetMu.RLock()	
	if !ah.announceValidatorSet[msg.Address] {
		logger.Debug("Received a message from a validator not within the announce validator set. Ignoring it.", "sender", msg.Address)
		ah.announceValSetMu.RUnlock()
		return errUnauthorizedAnnounceMessage
	}
	ah.announceValSetMu.RUnlock()

	var queryEnodeData QueryEnodeData
	err = rlp.DecodeBytes(msg.Msg, &queryEnodeData)
	if err != nil {
		logger.Warn("Error in decoding received Istanbul QueryEnode message content", "err", err, "IstanbulMsg", msg.String())
		return err
	}

	logger = logger.New("msgAddress", msg.Address, "msgVersion", queryEnodeData.Version)

	// Do some validation checks on the queryEnodeData
	if isValid, err := sb.validateQueryEnode(msg.Address, &queryEnodeData); !isValid || err != nil {
		logger.Warn("Validation of validationQuery message failed", "isValid", isValid, "err", err)
		return err
	}

	// If this is an elected or nearly elected validator, then process the announce message
	shouldProcessAnnounce, err := sb.shouldGenerateAndProcessAnnounce()
	if err != nil {
		logger.Warn("Error in checking if should process announce", err)
	}

	if shouldProcessAnnounce {
		logger.Trace("Processing an queryEnode message", "queryEnode encrypted enodeURLs", queryEnodeData.EncryptedEnodeURLs)
		for _, encryptedEnodeURL := range queryEnodeData.EncryptedEnodeURLs {
			// Only process an encryptedEnodeURL intended for this node
			if encryptedEnodeURL.DestAddress != sb.Address() {
				continue
			}
			enodeBytes, err := sb.decryptFn(accounts.Account{Address: sb.Address()}, encryptedEnodeURL.EncryptedEnodeURL, nil, nil)
			if err != nil {
				sb.logger.Warn("Error decrypting endpoint", "err", err)
				return err
			}
			enodeURL := string(enodeBytes)
			node, err := enode.ParseV4(enodeURL)
			if err != nil {
				logger.Warn("Error parsing enodeURL", "enodeUrl", enodeURL)
				return err
			}

		        if err := sb.valEnodeTable.Upsert(map[common.Address]*vet.AddressEntry{msg.address: {Node: node, Version: queryEnodeData.Version, PublicKey: signerPubKey}}); err != nil {
			    return err
			}

			break
		}
	}

	// Regossip this announce message
	return sb.regossipAnnounce(msg, announceData.Version, payload)
}

// validateQueryEnode will do some validation to check the contents of the queryEnode
// message. This is to force all validators that send an queryEnode message to
// create as succint message as possible, and prevent any possible network DOS attacks
// via extremely large queryEnode message.
func (ah *announceHandler) validateQueryEnode(msgAddress common.Address, queryEnodeData *queryEnodeData) (bool, error) {
	logger := sb.logger.New("func", "validateQueryEnode", "msg address", msgAddress)

	// Check if there are any duplicates in the announce message
	var encounteredAddresses = make(map[common.Address]bool)
	for _, encryptedEnodeURLRecord := range queryEnodeData.EncryptedEnodeURLs {
		if encounteredAddresses[encryptedEnodeURLRecord.DestAddress] {
			logger.Info("queryEnode message has duplicate entries", "address", queryEnodeRecord.DestAddress)
			return false, nil
		}

		encounteredAddresses[queryEnodeRecord.DestAddress] = true
	}

	// Check if the number of rows in the queryEnodePayload is at most 2 times the size of the current validator connection set.
	// Note that this is a heuristic of the actual size of validator connection set at the time the validator constructed the announce message.
	ah.announceValSetMu.RLock()
	if len(queryEnodeData.EncryptedEnodes) > 2 * len(ah.announceValidatorSet) {
		logger.Info("Number of announce message encrypted enodes is more than two times the size of the current validator connection set", "num announce enodes", len(announceData.AnnounceRecords), "reg/elected val set size", len(validatorConnSet))
		ah.announceValSetMu.RUnLock()		
		return false, err	   
	}
	ah.announceValSetMu.RUnLock()

	return true, nil
}

// regossipQueryEnode will regossip a received queryEnode message.
// If this node regossiped an queryEnode from the same source address within the last
// 5 minutes, then it won't regossip. This is to prevent a malicious validator from
// DOS'ing the network with very frequent queryEnode messages.
// This opens an attack vector where any malicious node could continue to gossip
// a previously gossiped announce message from any validator, causing other nodes to regossip and
// enforce the cooldown period for future messages originating from the origin validator.
func (ah *announceHandler) regossipQueryEnode(msg *istanbul.Message, announceVersion uint, payload []byte) error {
	logger := sb.logger.New("func", "regossipAnnounce", "announceSourceAddress", msg.Address, "announceVersion", announceVersion)

	sb.lastQueryEnodeGossipedMu.RLock()
	if lastGossiped, ok := sb.lastQueryEnodeGossiped[msg.Address]; ok {
		if time.Since(lastGossiped.Time) < queryEnodeGossipCooldownDuration {
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
	sb.lastQueryEnodeGossipedMu.RUnlock()

	logger.Trace("Regossiping the istanbul queryEnode message", "IstanbulMsg", msg.String())
	if err := sb.Multicast(nil, payload, istanbulQueryEnodeMsg); err != nil {
		return err
	}

	sb.lastQueryEnodeGossipedMu.Lock()
	sb.lastQueryEnodeGossiped[msg.Address] = &announceRegossip{
		Time:    time.Now(),
		Version: announceVersion,
	}
	sb.lastQueryEnodeGossipedMu.UnLock()

	return nil
}
