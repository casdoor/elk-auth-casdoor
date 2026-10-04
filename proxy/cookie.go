// Copyright 2022 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proxy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Session is what the session cookie holds after a user signs in.
type Session struct {
	Id          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName,omitempty"`
	Email       string `json:"email,omitempty"`
	ExpiresAt   int64  `json:"exp"`
}

// loginState is what the state cookie holds while a user signs in.
type loginState struct {
	ReturnTo  string `json:"returnTo"`
	ExpiresAt int64  `json:"exp"`
}

type signedValue struct {
	Kind string          `json:"kind"`
	Data json.RawMessage `json:"data"`
}

type signer struct {
	key []byte
}

func (s *signer) mac(payload string) string {
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// encode returns "<payload>.<signature>". kind keeps a value signed for one cookie
// from being accepted as another one.
func (s *signer) encode(kind string, v interface{}) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	value, err := json.Marshal(signedValue{Kind: kind, Data: data})
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(value)
	return payload + "." + s.mac(payload), nil
}

func (s *signer) decode(kind string, cookie string, v interface{}) error {
	payload, signature, ok := strings.Cut(cookie, ".")
	if !ok || !hmac.Equal([]byte(signature), []byte(s.mac(payload))) {
		return errors.New("invalid signature")
	}
	value, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return err
	}
	var signed signedValue
	if err = json.Unmarshal(value, &signed); err != nil {
		return err
	}
	if signed.Kind != kind {
		return errors.New("wrong cookie kind")
	}
	return json.Unmarshal(signed.Data, v)
}

func expired(expiresAt int64) bool {
	return time.Now().Unix() >= expiresAt
}
