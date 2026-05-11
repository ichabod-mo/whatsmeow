// Copyright (c) 2021 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"context"
	"encoding/binary"
	"fmt"
	"slices"
	"time"

	"go.mau.fi/libsignal/ecc"
	"go.mau.fi/libsignal/keys/identity"
	"go.mau.fi/libsignal/keys/prekey"
	"go.mau.fi/libsignal/util/optional"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/util/keys"
)

const (
	// WantedPreKeyCount is the number of prekeys that the client should upload to the WhatsApp servers in a single batch.
	WantedPreKeyCount = 50
	// MinPreKeyCount is the number of prekeys when the client will upload a new batch of prekeys to the WhatsApp servers.
	MinPreKeyCount = 50
)

func (cli *Client) getServerPreKeyCount(ctx context.Context) (int, error) {
	resp, err := cli.sendIQ(ctx, infoQuery{
		Namespace: "encrypt",
		Type:      "get",
		To:        types.ServerJID,
		Content: []waBinary.Node{
			{Tag: "count"},
		},
	})
	if err != nil {
		return 0, fmt.Errorf("failed to get prekey count on server: %w", err)
	}
	count := resp.GetChildByTag("count")
	ag := count.AttrGetter()
	val := ag.Int("value")
	return val, ag.Error()
}

func (cli *Client) getServerPreKeyID(ctx context.Context) ([]uint32, error) {
	digest, err := cli.getServerPreKeyDigest(ctx)
	if err != nil {
		return nil, err
	}
	return digest.PreKeyIDs, nil
}

func (cli *Client) getServerPreKeyDigest(ctx context.Context) (*serverPreKeyDigest, error) {
	resp, err := cli.sendIQ(ctx, infoQuery{
		Namespace: "encrypt",
		Type:      "get",
		To:        types.ServerJID,
		Content: []waBinary.Node{
			{Tag: "digest"},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get prekey digest on server: %w", err)
	}
	return parseServerPreKeyDigest(resp)
}

type serverPreKeyDigest struct {
	RegistrationID        uint32
	KeyType               byte
	IdentityKey           [32]byte
	SignedPreKeyID        uint32
	SignedPreKeyValue     [32]byte
	SignedPreKeySignature [64]byte
	PreKeyIDs             []uint32
}

func parseServerPreKeyDigest(resp *waBinary.Node) (*serverPreKeyDigest, error) {
	if resp == nil {
		return nil, fmt.Errorf("got empty response to prekey digest request")
	}
	digestNode, ok := resp.GetOptionalChildByTag("digest")
	if !ok {
		return nil, fmt.Errorf("prekey digest response did not contain digest")
	}

	registrationBytes, err := preKeyDigestChildBytes(digestNode, "registration", 4)
	if err != nil {
		return nil, err
	}
	keyTypeBytes, err := preKeyDigestChildBytes(digestNode, "type", 1)
	if err != nil {
		return nil, err
	}
	identityBytes, err := preKeyDigestChildBytes(digestNode, "identity", 32)
	if err != nil {
		return nil, err
	}
	signedPreKey, ok := digestNode.GetOptionalChildByTag("skey")
	if !ok {
		return nil, fmt.Errorf("prekey digest response did not contain skey")
	}
	signedPreKeyIDBytes, err := preKeyDigestChildBytes(signedPreKey, "id", 3)
	if err != nil {
		return nil, err
	}
	signedPreKeyValueBytes, err := preKeyDigestChildBytes(signedPreKey, "value", 32)
	if err != nil {
		return nil, err
	}
	signedPreKeySignatureBytes, err := preKeyDigestChildBytes(signedPreKey, "signature", 64)
	if err != nil {
		return nil, err
	}
	signedPreKeyID := preKeyIDFromBytes(signedPreKeyIDBytes)
	if signedPreKeyID < store.PreKeyIDMin || signedPreKeyID > store.PreKeyIDMax {
		return nil, fmt.Errorf("prekey digest signed prekey ID %d outside valid range %d..%d", signedPreKeyID, store.PreKeyIDMin, store.PreKeyIDMax)
	}
	list, ok := digestNode.GetOptionalChildByTag("list")
	if !ok {
		return nil, fmt.Errorf("prekey digest response did not contain list")
	}
	preKeyIDs, err := parsePreKeyIDList(list)
	if err != nil {
		return nil, err
	}

	digest := &serverPreKeyDigest{
		RegistrationID: binary.BigEndian.Uint32(registrationBytes),
		KeyType:        keyTypeBytes[0],
		SignedPreKeyID: signedPreKeyID,
		PreKeyIDs:      preKeyIDs,
	}
	copy(digest.IdentityKey[:], identityBytes)
	copy(digest.SignedPreKeyValue[:], signedPreKeyValueBytes)
	copy(digest.SignedPreKeySignature[:], signedPreKeySignatureBytes)
	return digest, nil
}

func parseServerPreKeyIDs(resp *waBinary.Node) ([]uint32, error) {
	digest, err := parseServerPreKeyDigest(resp)
	if err != nil {
		return nil, err
	}
	return digest.PreKeyIDs, nil
}

func preKeyDigestChildBytes(node waBinary.Node, tag string, expectedLength int) ([]byte, error) {
	child := node.GetChildByTag(tag)
	if child.Tag != tag {
		return nil, fmt.Errorf("prekey digest response did not contain %s", tag)
	}
	content, ok := child.Content.([]byte)
	if !ok {
		return nil, fmt.Errorf("prekey digest %s has unexpected content (%T)", tag, child.Content)
	} else if len(content) != expectedLength {
		return nil, fmt.Errorf("prekey digest %s has unexpected number of bytes (%d, expected %d)", tag, len(content), expectedLength)
	}
	return content, nil
}

func parsePreKeyIDList(list waBinary.Node) ([]uint32, error) {
	idNodes := list.GetChildrenByTag("id")
	ids := make([]uint32, 0, len(idNodes))
	seen := make(map[uint32]struct{}, len(idNodes))
	for _, idNode := range idNodes {
		idBytes, ok := idNode.Content.([]byte)
		if !ok {
			return nil, fmt.Errorf("prekey digest ID has unexpected content (%T)", idNode.Content)
		} else if len(idBytes) != 3 {
			return nil, fmt.Errorf("prekey digest ID has unexpected number of bytes (%d, expected 3)", len(idBytes))
		}
		id := preKeyIDFromBytes(idBytes)
		if id < store.PreKeyIDMin || id > store.PreKeyIDMax {
			return nil, fmt.Errorf("prekey digest ID %d outside valid range %d..%d", id, store.PreKeyIDMin, store.PreKeyIDMax)
		}
		if _, ok = seen[id]; ok {
			return nil, fmt.Errorf("prekey digest contained duplicate ID %d", id)
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids, nil
}

func (digest *serverPreKeyDigest) compareLocal(cli *Client) (bool, string) {
	switch {
	case digest.RegistrationID != cli.Store.RegistrationID:
		return false, "registration ID"
	case digest.KeyType != ecc.DjbType:
		return false, "key type"
	case cli.Store.IdentityKey == nil || cli.Store.IdentityKey.Pub == nil:
		return false, "local identity key"
	case digest.IdentityKey != *cli.Store.IdentityKey.Pub:
		return false, "identity key"
	case cli.Store.SignedPreKey == nil:
		return false, "local signed prekey"
	case digest.SignedPreKeyID != cli.Store.SignedPreKey.KeyID:
		return false, "signed prekey ID"
	case cli.Store.SignedPreKey.Pub == nil:
		return false, "local signed prekey value"
	case digest.SignedPreKeyValue != *cli.Store.SignedPreKey.Pub:
		return false, "signed prekey value"
	case cli.Store.SignedPreKey.Signature == nil:
		return false, "local signed prekey signature"
	case digest.SignedPreKeySignature != *cli.Store.SignedPreKey.Signature:
		return false, "signed prekey signature"
	default:
		return true, ""
	}
}

func preKeyIDFromBytes(idBytes []byte) uint32 {
	return binary.BigEndian.Uint32([]byte{0, idBytes[0], idBytes[1], idBytes[2]})
}

func preKeyIDToBytes(id uint32) []byte {
	var keyID [4]byte
	binary.BigEndian.PutUint32(keyID[:], id)
	return keyID[1:]
}

func preKeyIDsToNodes(ids []uint32) []waBinary.Node {
	nodes := make([]waBinary.Node, len(ids))
	for i, id := range ids {
		nodes[i] = waBinary.Node{Tag: "id", Content: preKeyIDToBytes(id)}
	}
	return nodes
}

func preKeyIDs(preKeys []*keys.PreKey) []uint32 {
	ids := make([]uint32, len(preKeys))
	for i, key := range preKeys {
		ids[i] = key.KeyID
	}
	return ids
}

type preKeyIDSetStatus uint8

const (
	preKeyIDSetEqual preKeyIDSetStatus = iota
	preKeyIDSetOverlap
	preKeyIDSetDisjoint
)

func comparePreKeyIDSets(localIDs, serverIDs []uint32) preKeyIDSetStatus {
	if len(localIDs) == 0 && len(serverIDs) == 0 {
		return preKeyIDSetEqual
	}
	localSet := make(map[uint32]struct{}, len(localIDs))
	for _, id := range localIDs {
		localSet[id] = struct{}{}
	}
	equal := len(localSet) == len(serverIDs)
	overlap := false
	seenServerIDs := make(map[uint32]struct{}, len(serverIDs))
	for _, id := range serverIDs {
		if _, duplicate := seenServerIDs[id]; duplicate {
			equal = false
			continue
		}
		seenServerIDs[id] = struct{}{}
		if _, ok := localSet[id]; ok {
			overlap = true
		} else {
			equal = false
		}
	}
	if equal {
		return preKeyIDSetEqual
	} else if overlap {
		return preKeyIDSetOverlap
	}
	return preKeyIDSetDisjoint
}

func splitServerAndRetryPreKeyIDs(ids []uint32) (serverIDs, retryIDs []uint32) {
	for _, id := range ids {
		switch {
		case id >= store.PreKeyServerIDMin && id <= store.PreKeyServerIDMax:
			serverIDs = append(serverIDs, id)
		case id >= store.PreKeyRetryIDMin && id <= store.PreKeyRetryIDMax:
			retryIDs = append(retryIDs, id)
		}
	}
	return serverIDs, retryIDs
}

func (cli *Client) deleteServerPreKeys(ctx context.Context, ids []uint32) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := cli.sendIQ(ctx, infoQuery{
		Namespace: "encrypt",
		Type:      "set",
		To:        types.ServerJID,
		Content: []waBinary.Node{{
			Tag: "op",
			Attrs: waBinary.Attrs{
				"mode": "delete",
			},
		}, {
			Tag: "list",
		}, {
			Tag: "pq_list",
		},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to delete prekeys on server: %w", err)
	}
	return nil
}

func (cli *Client) uploadPreKeys(ctx context.Context, initialUpload bool) bool {
	cli.uploadPreKeysLock.Lock()
	defer cli.uploadPreKeysLock.Unlock()
	if !initialUpload && cli.lastPreKeyUpload.Add(10*time.Minute).After(time.Now()) {
		sc, _ := cli.getServerPreKeyCount(ctx)
		if sc >= WantedPreKeyCount {
			cli.Log.Debugf("Canceling prekey upload request due to likely race condition")
			return false
		}
	}
	var registrationIDBytes [4]byte
	binary.BigEndian.PutUint32(registrationIDBytes[:], cli.Store.RegistrationID)
	wantedCount := WantedPreKeyCount
	if initialUpload {
		wantedCount = 812
	}
	preKeys, err := cli.Store.PreKeys.GetOrGenPreKeys(ctx, uint32(wantedCount))
	if err != nil {
		cli.Log.Errorf("Failed to get prekeys to upload: %v", err)
		return false
	} else if len(preKeys) == 0 {
		cli.Log.Warnf("No prekeys returned for upload")
		return false
	}
	cli.Log.Infof("Uploading %d new prekeys to server", len(preKeys))
	_, err = cli.sendIQ(ctx, infoQuery{
		Namespace: "encrypt",
		Type:      "set",
		To:        types.ServerJID,
		Content: []waBinary.Node{
			{Tag: "registration", Content: registrationIDBytes[:]},
			{Tag: "type", Content: []byte{ecc.DjbType}},
			{Tag: "identity", Content: cli.Store.IdentityKey.Pub[:]},
			{Tag: "list", Content: preKeysToNodes(preKeys)},
			preKeyToNode(cli.Store.SignedPreKey),
		},
	})
	if err != nil {
		cli.Log.Errorf("Failed to send request to upload prekeys: %v", err)
		return false
	}
	cli.Log.Debugf("Got response to uploading prekeys")
	err = cli.Store.PreKeys.MarkPreKeysAsUploaded(ctx, preKeyIDs(preKeys))
	if err != nil {
		cli.Log.Warnf("Failed to mark prekeys as uploaded: %v", err)
		return false
	}
	cli.lastPreKeyUpload = time.Now()
	return true
}

func (cli *Client) fetchPreKeysNoError(ctx context.Context, retryDevices []types.JID) map[types.JID]*prekey.Bundle {
	if len(retryDevices) == 0 {
		return nil
	}
	bundlesResp, err := cli.fetchPreKeys(ctx, retryDevices)
	if err != nil {
		cli.Log.Warnf("Failed to fetch prekeys for %v with no existing session: %v", retryDevices, err)
		return nil
	}
	bundles := make(map[types.JID]*prekey.Bundle, len(retryDevices))
	for _, jid := range retryDevices {
		resp := bundlesResp[jid]
		if resp.err != nil {
			cli.Log.Warnf("Failed to fetch prekey for %s: %v", jid, resp.err)
			continue
		}
		bundles[jid] = resp.bundle
	}
	return bundles
}

type preKeyResp struct {
	bundle *prekey.Bundle
	err    error
}

func (cli *Client) fetchPreKeys(ctx context.Context, users []types.JID) (map[types.JID]preKeyResp, error) {
	requests := make([]waBinary.Node, len(users))
	for i, user := range users {
		requests[i].Tag = "user"
		requests[i].Attrs = waBinary.Attrs{
			"jid":    user,
			"reason": "identity",
		}
	}
	resp, err := cli.sendIQ(ctx, infoQuery{
		Namespace: "encrypt",
		Type:      "get",
		To:        types.ServerJID,
		Content: []waBinary.Node{{
			Tag:     "key",
			Content: requests,
		}},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to send prekey request: %w", err)
	} else if len(resp.GetChildren()) == 0 {
		return nil, fmt.Errorf("got empty response to prekey request")
	}
	list := resp.GetChildByTag("list")
	respData := make(map[types.JID]preKeyResp)
	for _, child := range list.GetChildren() {
		if child.Tag != "user" {
			continue
		}
		jid := child.AttrGetter().JID("jid")
		bundle, err := nodeToPreKeyBundle(uint32(jid.Device), child)
		respData[jid] = preKeyResp{bundle, err}
	}
	return respData, nil
}

func preKeyToNode(key *keys.PreKey) waBinary.Node {
	node := waBinary.Node{
		Tag: "key",
		Content: []waBinary.Node{
			{Tag: "id", Content: preKeyIDToBytes(key.KeyID)},
			{Tag: "value", Content: key.Pub[:]},
		},
	}
	if key.Signature != nil {
		node.Tag = "skey"
		node.Content = append(node.GetChildren(), waBinary.Node{
			Tag:     "signature",
			Content: key.Signature[:],
		})
	}
	return node
}

func nodeToPreKeyBundle(deviceID uint32, node waBinary.Node) (*prekey.Bundle, error) {
	errorNode, ok := node.GetOptionalChildByTag("error")
	if ok && errorNode.Tag == "error" {
		return nil, fmt.Errorf("got error getting prekeys: %s", errorNode.XMLString())
	}

	registrationBytes, ok := node.GetChildByTag("registration").Content.([]byte)
	if !ok || len(registrationBytes) != 4 {
		return nil, fmt.Errorf("invalid registration ID in prekey response")
	}
	registrationID := binary.BigEndian.Uint32(registrationBytes)

	keysNode, ok := node.GetOptionalChildByTag("keys")
	if !ok {
		keysNode = node
	}

	identityKeyRaw, ok := keysNode.GetChildByTag("identity").Content.([]byte)
	if !ok || len(identityKeyRaw) != 32 {
		return nil, fmt.Errorf("invalid identity key in prekey response")
	}
	identityKeyPub := *(*[32]byte)(identityKeyRaw)

	preKeyNode, ok := keysNode.GetOptionalChildByTag("key")
	preKey := &keys.PreKey{}
	if ok {
		var err error
		preKey, err = nodeToPreKey(preKeyNode)
		if err != nil {
			return nil, fmt.Errorf("invalid prekey in prekey response: %w", err)
		}
	}

	signedPreKey, err := nodeToPreKey(keysNode.GetChildByTag("skey"))
	if err != nil {
		return nil, fmt.Errorf("invalid signed prekey in prekey response: %w", err)
	}

	var bundle *prekey.Bundle
	if ok {
		bundle = prekey.NewBundle(registrationID, deviceID,
			optional.NewOptionalUint32(preKey.KeyID), signedPreKey.KeyID,
			ecc.NewDjbECPublicKey(*preKey.Pub), ecc.NewDjbECPublicKey(*signedPreKey.Pub), *signedPreKey.Signature,
			identity.NewKey(ecc.NewDjbECPublicKey(identityKeyPub)))
	} else {
		bundle = prekey.NewBundle(registrationID, deviceID, optional.NewEmptyUint32(), signedPreKey.KeyID,
			nil, ecc.NewDjbECPublicKey(*signedPreKey.Pub), *signedPreKey.Signature,
			identity.NewKey(ecc.NewDjbECPublicKey(identityKeyPub)))
	}

	return bundle, nil
}

func nodeToPreKey(node waBinary.Node) (*keys.PreKey, error) {
	key := keys.PreKey{
		KeyPair:   keys.KeyPair{},
		KeyID:     0,
		Signature: nil,
	}
	if id := node.GetChildByTag("id"); id.Tag != "id" {
		return nil, fmt.Errorf("prekey node doesn't contain ID tag")
	} else if idBytes, ok := id.Content.([]byte); !ok {
		return nil, fmt.Errorf("prekey ID has unexpected content (%T)", id.Content)
	} else if len(idBytes) != 3 {
		return nil, fmt.Errorf("prekey ID has unexpected number of bytes (%d, expected 3)", len(idBytes))
	} else {
		key.KeyID = binary.BigEndian.Uint32(append([]byte{0}, idBytes...))
	}
	if pubkey := node.GetChildByTag("value"); pubkey.Tag != "value" {
		return nil, fmt.Errorf("prekey node doesn't contain value tag")
	} else if pubkeyBytes, ok := pubkey.Content.([]byte); !ok {
		return nil, fmt.Errorf("prekey value has unexpected content (%T)", pubkey.Content)
	} else if len(pubkeyBytes) != 32 {
		return nil, fmt.Errorf("prekey value has unexpected number of bytes (%d, expected 32)", len(pubkeyBytes))
	} else {
		key.KeyPair.Pub = (*[32]byte)(pubkeyBytes)
	}
	if node.Tag == "skey" {
		if sig := node.GetChildByTag("signature"); sig.Tag != "signature" {
			return nil, fmt.Errorf("prekey node doesn't contain signature tag")
		} else if sigBytes, ok := sig.Content.([]byte); !ok {
			return nil, fmt.Errorf("prekey signature has unexpected content (%T)", sig.Content)
		} else if len(sigBytes) != 64 {
			return nil, fmt.Errorf("prekey signature has unexpected number of bytes (%d, expected 64)", len(sigBytes))
		} else {
			key.Signature = (*[64]byte)(sigBytes)
		}
	}
	return &key, nil
}

func preKeysToNodes(prekeys []*keys.PreKey) []waBinary.Node {
	nodes := make([]waBinary.Node, len(prekeys))
	for i, key := range prekeys {
		nodes[i] = preKeyToNode(key)
	}
	return nodes
}
