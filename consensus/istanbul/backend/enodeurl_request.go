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

type enodeURLRequestData struct {
	EncryptedEnodeURLs []*encryptedEnodeURL
	Version         uint
}

// String returns a string representation of er
func (er *enodeURLRequestData) String() string {
	return fmt.Sprintf("{Version: %v, enodeURLRecords: %v}", er.Version, er.enodeURLRecords)
}

// EncodeRLP serializes ad into the Ethereum RLP format.
func (er *enodeURLRequestData) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, []interface{}{er.AnnounceRecords, er.Version})
}

// DecodeRLP implements rlp.Decoder, and load the ad fields from a RLP stream.
func (er *enodeURLRequestData) DecodeRLP(s *rlp.Stream) error {
	var msg struct {
		EncryptedEnodeURLs []*encryptedEnodeURL
		Version         uint
	}

	if err := s.Decode(&msg); err != nil {
		return err
	}
	er.EncryptedEnodeURLs, er.Version = msg.EncrypedEnodeURLs, msg.Version
	return nil
}


// generateAndGossipEnodeURLRequest will generate the a enodeUrl request msg
// and broadcast it to it's peers, which should then regossip it throughout the
// p2p network.
func (an *announceHandler) generateAndGossipEnodeURLRequest(version uint, destAddresses []common.Address) (bool, error) {
	logger := sb.logger.New("func", "generateAndGossipEnodeURLRequest")
	logger.Trace("generateAndGossipEnodeURLRequest called")
	msg, err := sb.generateEnodeURLRequest(version)
	if err != nil || msg == nil {
		return false, err
	}

	// Convert to payload
	payload, err := msg.Payload()
	if err != nil {
		logger.Error("Error in converting EnodeURLRequest Message to payload", "EnodeURLRequestMsg", msg.String(), "err", err)
		return true, err
	}

	if err := sb.Multicast(nil, payload, istanbulEnodeURLRequestMsg); err != nil {
		return true, err
	}
	
	return true, nil
}

// generateEnodeURLRequest returns an enodeURLRequest message from this node with a given version.
func (an *announceHandler) generateEnodeURLRequest(version uint, destAddresses []common.Address) (*istanbul.Message, error) {
	logger := sb.logger.New("func", "generateEnodeURLRequest")

	enodeURL, err := sb.getEnodeURL()
	if err != nil {
		logger.Error("Error getting enode URL", "err", err)
		return nil, err
	}
	encryptedEnodeURLs, err := sb.generateEncryptedEnodeURLs(enodeURL, destAddresses)
	if err != nil {
		logger.Warn("Error generating encrypted enodeurls", "err", err)
		return nil, err
	}
	if len(encryptedEnodeURLs) == 0 {
		logger.Trace("No encrypted enodeURLs were generated")
		return nil, nil
	}
	enodeURLRequestData := &enodeURLRequestData{
		EncryptedEnodeURLs: encryptedEnodeURLs
		Version:         version,
	}

	enodeURLRequestBytes, err := rlp.EncodeToBytes(enodeURLRequestData)
	if err != nil {
		logger.Error("Error encoding enodeURLRequest data", "enodeURLRequestData", enodeURLRequestData.String(), "err", err)
		return nil, err
	}

	msg := &istanbul.Message{
		Code:      istanbulEnodeURLRequestMsg,
		Msg:       enodeURLRequestBytes,
		Address:   sb.Address(),
		Signature: []byte{},
	}

	// Sign the announce message
	if err := msg.Sign(sb.Sign); err != nil {
		logger.Error("Error in signing an EnodeURLRequest Message", "generateEnodeURLRequestMsg", msg.String(), "err", err)
		return nil, err
	}

	logger.Debug("Generated an EnodeURLRequest message", "IstanbulMsg", msg.String(), "enodeURLRequestData", enodeURLRequestData.String())

	return msg, nil
}


// generateEncryptedEnodeURLs returns the encrypted enodeURLs intended for validators
// whose entries in the val enode table do not exist or are outdated when compared
// to the signed announce version table.
func (an *announceHandler) generateEncryptedEnodeURLs(enodeURL string, destAddresses []common.Address) ([]*encryptedEnodeURL, error) {
	valEnodeEntries, err := ah.valEnodeTable.GetAllValEnodes()
	if err != nil {
		return nil, err
	}

	encryptedEnodeURLs := []*encryptedEnodeURL
	for address, valEnodeEntry := range valEnodeEntries {
		// Don't generate an announce record for ourselves
		if address == sb.Address() {
			continue
		}

		if valEnodeEntry.Version == valEnodeEntry.MaxKnownVersion {
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
	}
	return encryptedEnodeURLs, nil
}

// This function will handle an announce message.
func (sb *Backend) handleAnnounceMsg(peer consensus.Peer, payload []byte) error {
	logger := sb.logger.New("func", "handleAnnounceMsg")

	msg := new(istanbul.Message)

	// Decode message
	err := msg.FromPayload(payload, istanbul.GetSignatureAddress)
	if err != nil {
		logger.Error("Error in decoding received Istanbul Announce message", "err", err, "payload", hex.EncodeToString(payload))
		return err
	}
	logger.Trace("Handling an IstanbulAnnounce message", "from", msg.Address)

	// Check if the sender is within the validator connection set
	validatorConnSet, err := sb.retrieveValidatorConnSet()
	if err != nil {
		logger.Trace("Error in retrieving validator connection set", "err", err)
		return err
	}

	if !validatorConnSet[msg.Address] {
		logger.Debug("Received a message from a validator not within the validator connection set. Ignoring it.", "sender", msg.Address)
		return errUnauthorizedAnnounceMessage
	}

	var announceData announceData
	err = rlp.DecodeBytes(msg.Msg, &announceData)
	if err != nil {
		logger.Warn("Error in decoding received Istanbul Announce message content", "err", err, "IstanbulMsg", msg.String())
		return err
	}

	logger = logger.New("msgAddress", msg.Address, "msgVersion", announceData.Version)

	// Do some validation checks on the announceData
	if isValid, err := sb.validateAnnounce(msg.Address, &announceData); !isValid || err != nil {
		logger.Warn("Validation of announce message failed", "isValid", isValid, "err", err)
		return err
	}

	// If this is an elected or nearly elected validator, then process the announce message
	shouldProcessAnnounce, err := sb.shouldGenerateAndProcessAnnounce()
	if err != nil {
		logger.Warn("Error in checking if should process announce", err)
	}

	if shouldProcessAnnounce {
		logger.Trace("Processing an announce message", "announce records", announceData.AnnounceRecords)
		for _, announceRecord := range announceData.AnnounceRecords {
			// Only process an announceRecord intended for this node
			if announceRecord.DestAddress != sb.Address() {
				continue
			}
			enodeBytes, err := sb.decryptFn(accounts.Account{Address: sb.Address()}, announceRecord.EncryptedEnodeURL, nil, nil)
			if err != nil {
				sb.logger.Warn("Error decrypting endpoint", "err", err, "announceRecord.EncryptedEnodeURL", announceRecord.EncryptedEnodeURL)
				return err
			}
			enodeURL := string(enodeBytes)
			node, err := enode.ParseV4(enodeURL)
			if err != nil {
				logger.Warn("Error parsing enodeURL", "enodeUrl", enodeURL)
				return err
			}
			sb.lastAnnounceAnsweredMu.Lock()
			// Don't answer an announce message that's been answered too recently
			if lastAnswered, ok := sb.lastAnnounceAnswered[msg.Address]; !ok || time.Since(lastAnswered) < announceAnswerCooldownDuration {
				if err := sb.answerAnnounceMsg(msg.Address, node, announceData.Version); err != nil {
					logger.Warn("Error answering an announce msg", "target node", node.URLv4(), "error", err)
					sb.lastAnnounceAnsweredMu.Unlock()
					return err
				}
				sb.lastAnnounceAnswered[msg.Address] = time.Now()
			}
			sb.lastAnnounceAnsweredMu.Unlock()
			break
		}
	}

	// Regossip this announce message
	return sb.regossipAnnounce(msg, announceData.Version, payload, false)
}
