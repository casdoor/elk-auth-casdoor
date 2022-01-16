// Copyright 2022 The casbin Authors. All Rights Reserved.
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
package object

import (
	"fmt"
	"math/rand"
	"net/http"
	"sync"
)

type RequestStateMem struct {
	sync.Mutex
	requestSession map[int]*http.Request
}

func NewRequestStateMem() RequestState {
	return &RequestStateMem{
		requestSession: make(map[int]*http.Request),
	}
}

func (r *RequestStateMem) AddRequest(req *http.Request) int {
	r.Lock()
	defer r.Unlock()
	state := rand.Intn(0x7fffffff)
	r.requestSession[state] = req
	return state
}

func (r *RequestStateMem) GetRequest(state int) (*http.Request, error) {
	r.Lock()
	defer r.Unlock()

	if req, ok := r.requestSession[state]; ok {
		return req, nil
	}
	return nil, fmt.Errorf("request for state %d not found in requestState", state)
}

func (r *RequestStateMem) DeleteRequest(state int) error {
	r.Lock()
	defer r.Unlock()

	if _, ok := r.requestSession[state]; ok {
		delete(r.requestSession, state)
		return nil
	}
	return fmt.Errorf("request for state %d not found in requestState", state)
}
