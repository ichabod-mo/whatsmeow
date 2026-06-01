// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

// QRLoginMode controls which handshake is used for QR login.
//
// The default is QRLoginModeClassic to preserve the existing behavior.
type QRLoginMode string

const (
	QRLoginModeDefault QRLoginMode = ""
	QRLoginModeClassic QRLoginMode = "classic"
	QRLoginModeXXKEM   QRLoginMode = "xxkem"
)

func (cli *Client) shouldUseXXKEMQRLogin() bool {
	return cli != nil && cli.Store != nil && cli.Store.ID == nil && cli.QRLoginMode == QRLoginModeXXKEM
}
