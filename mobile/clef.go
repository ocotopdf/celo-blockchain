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

package geth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/signer/core"
	"github.com/ethereum/go-ethereum/signer/fourbyte"
	"github.com/ethereum/go-ethereum/signer/rules"
	"github.com/ethereum/go-ethereum/signer/storage"
)

type encryptedSeedStorage struct {
	Description string              `json:"description"`
	Version     int                 `json:"version"`
	Params      keystore.CryptoJSON `json:"params"`
}

// ClefSignerConfig represents the collection of configuration values to fine tune the Clef
// signer embedded into a mobile process. The available values are a subset of the
// entire API provided by go-ethereum to reduce the maintenance surface and dev
// complexity.
type ClefSignerConfig struct {
	// If enabled, issues warnings instead of rejections for suspicious requests. Default off
	Advanced bool
	// File used to emit audit logs. Set to \"\" to disable
	AuditLog string
	// Chain id to use for signing (1=mainnet, 3=Ropsten, 4=Rinkeby, 5=Goerli)
	ChainId int64
	// Directory for Clef configuration
	ConfigDir string
	// File used for writing new 4byte-identifiers submitted via API
	CustomDB string
	// Filename for IPC socket/pipe within the datadir (explicit paths escape it)
	IPCPath string
	// Directory for the keystore
	Keystore string
	// Reduce key-derivation RAM & CPU usage at some expense of KDF strength
	LightKDF bool
	// Disables monitoring for and managing USB hardware wallets
	NoUSB bool
	// Path to the rule file to auto-authorize requests with
	Rules string
	// A file containing the (encrypted) master seed to encrypt Clef data, e.g. keystore credentials and ruleset hash
	SignerSecret string
	// Path to the smartcard daemon (pcscd) socket file
	SmartCardDaemonPath string
}

// defaultClefSignerConfig contains the default node configuration values to use if all
// or some fields are missing from the user's specified list.
var defaultClefSignerConfig = &ClefSignerConfig{
	ConfigDir: "",
	CustomDB:  "./4byte-custom.json",
}

// NewClefSignerConfig creates a new node option set, initialized to the default values.
func NewClefSignerConfig() *ClefSignerConfig {
	config := *defaultClefSignerConfig
	return &config
}

// Signer represents a Clef signer instance.
type ClefSigner struct {
	am      *accounts.Manager
	apiImpl *core.SignerAPI
}

func NewUI() *core.StdIOUI {
	client, err := rpc.DialContext(context.Background(), "stdio://")
	if err != nil {
		log.Crit("Could not create stdio client", "err", err)
	}
	ui := &core.StdIOUI{client: *client}
	return ui
}

// NewSigner creates and configures a new Clef signer.
func NewClefSigner(datadir string, config *ClefSignerConfig) (stack *ClefSigner, _ error) {
	// If no or partial configurations were specified, use defaults
	if config == nil {
		config = NewClefSignerConfig()
	}

	var (
		ui core.UIClientAPI
	)
	ui = NewUI()

	// 4bytedb data
	db, err := fourbyte.NewWithFile(config.CustomDB)
	if err != nil {
		return nil, err
	}
	embeds, locals := db.Size()
	log.Info("Loaded 4byte database", "embeds", embeds, "locals", locals, "local", config.CustomDB)

	var (
		api       core.ExternalAPI
		pwStorage storage.Storage = &storage.NoStorage{}
	)

	if stretchedKey, err := readMasterKey(config.ConfigDir, config.SignerSecret, ui, nil); err != nil {
		log.Warn("Failed to open master, rules disabled", "err", err)
	} else {
		vaultLocation := filepath.Join(config.ConfigDir, common.Bytes2Hex(crypto.Keccak256([]byte("vault"), stretchedKey)[:10]))

		// Generate domain specific keys
		pwkey := crypto.Keccak256([]byte("credentials"), stretchedKey)
		jskey := crypto.Keccak256([]byte("jsstorage"), stretchedKey)
		confkey := crypto.Keccak256([]byte("config"), stretchedKey)

		// Initialize the encrypted storages
		pwStorage = storage.NewAESEncryptedStorage(filepath.Join(vaultLocation, "credentials.json"), pwkey)
		jsStorage := storage.NewAESEncryptedStorage(filepath.Join(vaultLocation, "jsstorage.json"), jskey)
		configStorage := storage.NewAESEncryptedStorage(filepath.Join(vaultLocation, "config.json"), confkey)

		// Do we have a rule-file?
		if config.Rules != "" {
			ruleJS, err := ioutil.ReadFile(config.Rules)
			if err != nil {
				log.Warn("Could not load rules, disabling", "file", config.Rules, "err", err)
			} else {
				shasum := sha256.Sum256(ruleJS)
				foundShaSum := hex.EncodeToString(shasum[:])
				storedShasum, _ := configStorage.Get("ruleset_sha256")
				if storedShasum != foundShaSum {
					log.Warn("Rule hash not attested, disabling", "hash", foundShaSum, "attested", storedShasum)
				} else {
					// Initialize rules
					ruleEngine, err := rules.NewRuleEvaluator(ui, jsStorage)
					if err != nil {
						return nil, err
					}
					ruleEngine.Init(string(ruleJS))
					ui = ruleEngine
					log.Info("Rule engine configured", "file", config.Rules)
				}
			}
		}
	}
	log.Info("Starting signer", "chainid", config.ChainId, "keystore", config.Keystore,
		"light-kdf", config.LightKDF, "advanced", config.Advanced)
	am := core.StartClefAccountManager(config.Keystore, config.NoUSB, config.LightKDF, config.SmartCardDaemonPath)
	apiImpl := core.NewSignerAPI(am, config.ChainId, config.NoUSB, ui, db, config.Advanced, pwStorage)

	// Establish the bidirectional communication, by creating a new UI backend and registering
	// it with the UI.
	ui.RegisterUIServer(core.NewUIServerAPI(apiImpl))
	api = apiImpl
	// Audit logging
	if config.AuditLog != "" {
		api, err = core.NewAuditLogger(config.AuditLog, api)
		if err != nil {
			return nil, err
		}
		log.Info("Audit logs configured", "file", config.AuditLog)
	}
	// register signer API with server
	var (
		extapiURL = "n/a"
		ipcapiURL = "n/a"
	)
	rpcAPI := []rpc.API{
		{
			Namespace: "account",
			Public:    true,
			Service:   api,
			Version:   "1.0"},
	}

	ipcapiURL = filepath.Join(config.ConfigDir, filepath.Join(config.IPCPath, "clef.ipc"))
	listener, _, err := rpc.StartIPCEndpoint(ipcapiURL, rpcAPI)
	if err != nil {
		return nil, err
	}
	log.Info("IPC endpoint opened", "url", ipcapiURL)
	defer func() {
		listener.Close()
		log.Info("IPC endpoint closed", "url", ipcapiURL)
	}()

	ui.OnSignerStartup(core.StartupInfo{
		Info: map[string]interface{}{
			"intapi_version": core.InternalAPIVersion,
			"extapi_version": core.ExternalAPIVersion,
			"extapi_http":    extapiURL,
			"extapi_ipc":     ipcapiURL,
		},
	})

	return &ClefSigner{am, apiImpl}, nil
}

// Close terminates a running node along with all it's services, tearing internal
// state doen too. It's not possible to restart a closed node.
func (n *ClefSigner) Close() error {
	return nil
}

// Start creates a live P2P node and starts running it.
func (n *ClefSigner) Start() error {
	return nil
}

// Stop terminates a running node along with all it's services. If the node was
// not started, an error is returned.
func (n *ClefSigner) Stop() error {
	return nil
}

func readMasterKey(configDir, signerSecret string, ui core.UIClientAPI, masterPassword *string) ([]byte, error) {
	var (
		file string
	)
	if signerSecret != "" {
		file = signerSecret
	} else {
		file = filepath.Join(configDir, "masterseed.json")
	}
	if err := checkFile(file); err != nil {
		return nil, err
	}
	cipherKey, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var password string
	// If ui is not nil, get the password from ui.
	if ui != nil {
		resp, err := ui.OnInputRequired(core.UserInputRequest{
			Title:      "Master Password",
			Prompt:     "Please enter the password to decrypt the master seed",
			IsPassword: true})
		if err != nil {
			return nil, err
		}
		password = resp.Text
	} else if masterPassword != nil {
		password = *masterPassword
	} else {
		return nil, fmt.Errorf("No UI and no password provided")
	}
	masterSeed, err := decryptSeed(cipherKey, password)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt the master seed of clef")
	}
	if len(masterSeed) < 256 {
		return nil, fmt.Errorf("master seed of insufficient length, expected >255 bytes, got %d", len(masterSeed))
	}
	// Create vault location
	vaultLocation := filepath.Join(configDir, common.Bytes2Hex(crypto.Keccak256([]byte("vault"), masterSeed)[:10]))
	err = os.Mkdir(vaultLocation, 0700)
	if err != nil && !os.IsExist(err) {
		return nil, err
	}
	return masterSeed, nil
}

// decryptSeed decrypts the master seed
func decryptSeed(keyjson []byte, auth string) ([]byte, error) {
	var encSeed encryptedSeedStorage
	if err := json.Unmarshal(keyjson, &encSeed); err != nil {
		return nil, err
	}
	if encSeed.Version != 1 {
		log.Warn(fmt.Sprintf("unsupported encryption format of seed: %d, operation will likely fail", encSeed.Version))
	}
	seed, err := keystore.DecryptDataV3(encSeed.Params, auth)
	if err != nil {
		return nil, err
	}
	return seed, err
}

// checkFile is a convenience function to check if a file
// * exists
// * is mode 0400
func checkFile(filename string) error {
	info, err := os.Stat(filename)
	if err != nil {
		return fmt.Errorf("failed stat on %s: %v", filename, err)
	}
	// Check the unix permission bits
	if info.Mode().Perm()&0377 != 0 {
		return fmt.Errorf("file (%v) has insecure file permissions (%v)", filename, info.Mode().String())
	}
	return nil
}
