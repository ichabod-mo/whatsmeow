// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"context"
	"fmt"
	"time"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
)

const (
	// tcTokenBucketDuration is the duration of a single bucket in seconds (7 days).
	// Matches AB prop tctoken_duration.
	tcTokenBucketDuration = 604800
	// tcTokenNumBuckets is the number of rolling buckets (4 = ~28-day window).
	// Matches AB prop tctoken_num_buckets.
	tcTokenNumBuckets      = 4
	tcTokenDBPruneInterval = 24 * time.Hour
)

var (
	// TCTokenRequestTimeout is how long SendMessage waits for a freshly requested tctoken
	// to arrive via the privacy_token notification before falling back to cstoken/no token.
	TCTokenRequestTimeout = 3 * time.Second
	// TCTokenRequestPollInterval controls how often the privacy token store is checked
	// after requesting a fresh tctoken.
	TCTokenRequestPollInterval = 200 * time.Millisecond
)

func currentTCTokenCutoffTimestamp() time.Time {
	currentBucket := time.Now().Unix() / tcTokenBucketDuration
	cutoffBucket := currentBucket - (tcTokenNumBuckets - 1)
	return time.Unix(cutoffBucket*tcTokenBucketDuration, 0)
}

func isTCTokenExpired(timestamp time.Time) bool {
	if timestamp.IsZero() {
		return true
	}
	return timestamp.Before(currentTCTokenCutoffTimestamp())
}

// shouldSendNewTCToken returns true when the current bucket is newer than the last issuance bucket.
func shouldSendNewTCToken(senderTimestamp time.Time) bool {
	if senderTimestamp.IsZero() {
		return true
	}
	now := time.Now().Unix()
	return now/tcTokenBucketDuration > senderTimestamp.Unix()/tcTokenBucketDuration
}

func shouldSendTCTokenInChatAction(jid types.JID) bool {
	jid = jid.ToNonAD()
	return (jid.Server == types.DefaultUserServer || jid.Server == types.HiddenUserServer) &&
		jid.User != types.PSAJID.User &&
		!jid.IsBot()
}

func (cli *Client) resolveTCTokenStorageLID(ctx context.Context, jid types.JID) types.JID {
	storageJID := jid.ToNonAD()
	if storageJID.Server != types.DefaultUserServer || cli.Store == nil || cli.Store.LIDs == nil {
		return storageJID
	}
	lid, err := cli.Store.LIDs.GetLIDForPN(ctx, storageJID)
	if err != nil {
		cli.Log.Debugf("Failed to resolve LID for tctoken JID %s: %v", storageJID, err)
		return storageJID
	}
	if lid.IsEmpty() {
		return storageJID
	}
	return lid.ToNonAD()
}

// getTCTokenSenderTS reads the in-memory sender timestamp for a JID.
func (cli *Client) getTCTokenSenderTS(jid types.JID) time.Time {
	cli.tcTokenSenderTSLock.Lock()
	defer cli.tcTokenSenderTSLock.Unlock()

	return cli.tcTokenSenderTS[jid.ToNonAD()]
}

func (cli *Client) validateAndSetTCTokenSenderTS(jid types.JID, storedSenderTimestamp time.Time) bool {
	cli.tcTokenSenderTSLock.Lock()
	defer cli.tcTokenSenderTSLock.Unlock()

	key := jid.ToNonAD()
	if _, ok := cli.tcTokenSenderTS[key]; ok {
		return true
	}
	if storedSenderTimestamp.IsZero() || storedSenderTimestamp.Before(currentTCTokenCutoffTimestamp()) {
		return false
	}
	cli.tcTokenSenderTS[key] = storedSenderTimestamp
	cli.unlockedCleanupTCTokenSenderTSMap()
	return true
}

// setTCTokenSenderTS writes the in-memory sender timestamp for a JID.
func (cli *Client) setTCTokenSenderTS(jid types.JID, ts time.Time) {
	cli.tcTokenSenderTSLock.Lock()
	defer cli.tcTokenSenderTSLock.Unlock()

	cli.tcTokenSenderTS[jid.ToNonAD()] = ts
	cli.unlockedCleanupTCTokenSenderTSMap()
}

func (cli *Client) unlockedCleanupTCTokenSenderTSMap() {
	if time.Since(cli.lastTCTokenSenderTSCleanup) < tcTokenBucketDuration*time.Second {
		return
	}
	cli.lastTCTokenSenderTSCleanup = time.Now()
	cutoffTimestamp := currentTCTokenCutoffTimestamp()
	for jid, ts := range cli.tcTokenSenderTS {
		if ts.Before(cutoffTimestamp) {
			delete(cli.tcTokenSenderTS, jid)
		}
	}
}

func (cli *Client) loadStoredTCToken(ctx context.Context, storageJID types.JID) ([]byte, error) {
	existing, err := cli.Store.PrivacyTokens.GetPrivacyToken(ctx, storageJID)
	if err != nil {
		return nil, fmt.Errorf("failed to get privacy token: %w", err)
	}
	if existing == nil {
		return nil, nil
	}
	cli.validateAndSetTCTokenSenderTS(storageJID, existing.SenderTimestamp)
	if len(existing.Token) > 0 && !isTCTokenExpired(existing.Timestamp) {
		return existing.Token, nil
	}
	return nil, nil
}

// ensureTCToken returns a stored non-expired tctoken for the given JID, requesting one first if needed.
func (cli *Client) ensureTCToken(ctx context.Context, jid types.JID) (token []byte, err error) {
	cli.deleteExpiredPrivacyTokens()
	storageJID := cli.resolveTCTokenStorageLID(ctx, jid)
	token, err = cli.loadStoredTCToken(ctx, storageJID)
	if err != nil {
		return nil, err
	}
	if len(token) > 0 || !shouldSendTCTokenInChatAction(jid) {
		return token, nil
	}

	return cli.requestAndLoadTCToken(ctx, storageJID)
}

func (cli *Client) requestAndLoadTCToken(ctx context.Context, storageJID types.JID) ([]byte, error) {
	senderTimestamp := time.Now()
	resp, err := cli.issuePrivacyToken(ctx, storageJID, senderTimestamp)
	if err != nil {
		return nil, fmt.Errorf("failed to request privacy token: %w", err)
	}
	cli.setTCTokenSenderTS(storageJID, senderTimestamp)

	if token, err := cli.storeTCTokenFromIQResponse(ctx, storageJID, senderTimestamp, resp); err != nil {
		cli.Log.Debugf("Failed to parse tctoken response for %s: %v", storageJID, err)
	} else if len(token) > 0 {
		return token, nil
	}

	token, err := cli.loadStoredTCToken(ctx, storageJID)
	if err != nil || len(token) > 0 || TCTokenRequestTimeout <= 0 {
		return token, err
	}
	pollInterval := TCTokenRequestPollInterval
	if pollInterval <= 0 {
		pollInterval = 200 * time.Millisecond
	}

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	timeout := time.NewTimer(TCTokenRequestTimeout)
	defer timeout.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			token, err = cli.loadStoredTCToken(ctx, storageJID)
			if err != nil || len(token) > 0 {
				return token, err
			}
		case <-timeout.C:
			return nil, nil
		}
	}
}

func (cli *Client) storeTCTokenFromIQResponse(ctx context.Context, storageJID types.JID, senderTimestamp time.Time, resp *waBinary.Node) ([]byte, error) {
	if resp == nil {
		return nil, nil
	}
	tokens := resp.GetChildByTag("tokens")
	if tokens.Tag != "tokens" {
		return nil, nil
	}
	for _, child := range tokens.GetChildren() {
		if child.Tag != "token" {
			continue
		}
		ag := child.AttrGetter()
		if ag.String("type") != "trusted_contact" {
			continue
		}
		token, ok := child.Content.([]byte)
		if !ok || len(token) == 0 {
			continue
		}
		timestamp := ag.UnixTime("t")
		if timestamp.IsZero() {
			timestamp = time.Now()
		}
		if err := cli.Store.PrivacyTokens.PutPrivacyTokens(ctx, store.PrivacyToken{
			User:            storageJID,
			Token:           token,
			Timestamp:       timestamp,
			SenderTimestamp: senderTimestamp,
		}); err != nil {
			return nil, err
		}
		return token, nil
	}
	return nil, nil
}

func (cli *Client) deleteExpiredPrivacyTokens() {
	if !cli.tcTokenDBPruneLock.TryLock() {
		return
	}
	if time.Since(cli.lastTCTokenDBPrune) < tcTokenDBPruneInterval {
		cli.tcTokenDBPruneLock.Unlock()
		return
	}
	cli.lastTCTokenDBPrune = time.Now()
	go func() {
		defer cli.tcTokenDBPruneLock.Unlock()
		deleted, err := cli.Store.PrivacyTokens.DeleteExpiredPrivacyTokens(cli.BackgroundEventCtx, currentTCTokenCutoffTimestamp())
		if err != nil {
			cli.Log.Warnf("Failed to remove expired tctokens from DB: %v", err)
		} else if deleted > 0 {
			cli.Log.Debugf("Removed %d expired tctokens from DB", deleted)
		}
	}()
}

// Only called when a bucket boundary has been crossed since the last issuance.
func (cli *Client) issuePrivacyTokenAndSave(jid types.JID, senderTimestamp time.Time) {
	ctx := cli.BackgroundEventCtx
	storageJID := jid.ToNonAD()
	_, err := cli.issuePrivacyToken(ctx, storageJID, senderTimestamp)
	if err != nil {
		cli.Log.Errorf("Failed to issue privacy token for %s: %v", jid, err)
		return
	}
	cli.setTCTokenSenderTS(storageJID, senderTimestamp)
	// TODO replace with an UPDATE call instead of get+put
	existing, err := cli.Store.PrivacyTokens.GetPrivacyToken(ctx, storageJID)
	if err != nil {
		cli.Log.Errorf("Failed to load tctoken while persisting sender timestamp for %s: %v", jid, err)
		return
	}
	if existing == nil || len(existing.Token) == 0 {
		return
	}
	existing.SenderTimestamp = senderTimestamp
	if err = cli.Store.PrivacyTokens.PutPrivacyTokens(ctx, *existing); err != nil {
		cli.Log.Errorf("Failed to persist privacy token sender timestamp for %s: %v", jid, err)
	}
}

// issuePrivacyToken sends an IQ to the server to issue a privacy token for the given JID.
func (cli *Client) issuePrivacyToken(ctx context.Context, jid types.JID, timestamp time.Time) (*waBinary.Node, error) {
	return cli.sendIQ(ctx, infoQuery{
		Namespace: "privacy",
		Type:      iqSet,
		To:        types.ServerJID,
		Content: []waBinary.Node{{
			Tag: "tokens",
			Content: []waBinary.Node{{
				Tag: "token",
				Attrs: waBinary.Attrs{
					"jid":  jid.ToNonAD(),
					"t":    fmt.Sprintf("%d", timestamp.Unix()),
					"type": "trusted_contact",
				},
			}},
		}},
	})
}
