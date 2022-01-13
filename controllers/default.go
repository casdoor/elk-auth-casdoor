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
package controllers

import (
	"bytes"
	"context"
	_ "embed"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"

	"github.com/astaxie/beego"
	"github.com/astaxie/beego/logs"
	"github.com/casdoor/casdoor-go-sdk/auth"
	"github.com/casdoor/elk-auth-casdoor/object"
)

var proxy *httputil.ReverseProxy
var requestState object.RequestState
var callbaskURL = ""

//go:embed token_jwt_key.pem
var tokenJWT string

func init() {
	auth.InitConfig(
		beego.AppConfig.String("casdoorEndpoint"),
		beego.AppConfig.String("clientID"),
		beego.AppConfig.String("clientSecret"),
		tokenJWT,
		beego.AppConfig.String("organization"),
		beego.AppConfig.String("appName"),
	)
	remote, err := url.Parse(beego.AppConfig.String("targetEndpoint"))
	if err != nil {
		logs.Alert("invalid targetEndpoint: " + err.Error())
	}
	proxy = httputil.NewSingleHostReverseProxy(remote)
	requestState = object.NewRequestStateMem()

	local, err := url.Parse(beego.AppConfig.String("pluginEndpoint"))
	if err != nil {
		logs.Alert("invalid targetEndpoint: " + err.Error())
	}
	local.Path = "/callback"
	callbaskURL = local.String()
}

type MainController struct {
	beego.Controller
}

func (c *MainController) MainHandler() {
	session := c.GetSession("username")
	state := c.GetSession("elk-auth-state")
	if session == nil && state != nil {
		logs.Alert("no session for specified state")
		stateInt, ok := state.(int)
		if ok {
			requestState.DeleteRequest(stateInt)
		}
		state = nil
	}

	if session == nil && state == nil {
		//this user has never logged in, jump to casdoor login page
		casdoorUrl, err := url.Parse(beego.AppConfig.String("casdoorEndpoint"))
		if err != nil {
			c.returnError(err.Error(), http.StatusInternalServerError)
			return
		}
		req := c.Ctx.Request
		req.Body = io.NopCloser(bytes.NewBuffer(c.Ctx.Input.RequestBody))
		newState := requestState.AddRequest(req)
		c.SetSession("elk-auth-state", newState)
		//construcu url for /login/oauth/authorize?client_id=xxx&response_type=code&redirect_uri=xxx&scope=read&state=xxx
		casdoorUrl.Path = "/login/oauth/authorize"
		values := url.Values{}
		values.Add("state", strconv.Itoa(newState))
		values.Add("response_type", "code")
		values.Add("scope", "read")
		values.Add("client_id", beego.AppConfig.String("clientID"))
		values.Add("redirect_uri", callbaskURL)
		casdoorUrl.RawQuery = values.Encode()
		c.Redirect(casdoorUrl.String(), http.StatusTemporaryRedirect)
		return
	} else if session != nil && state != nil {
		//this user has just logged in, and previous request is required
		stateInt, ok := state.(int)
		if !ok {
			c.returnError("failed to resolve state", http.StatusInternalServerError)
			return
		}

		req, err := requestState.GetRequest(stateInt)
		req = req.Clone(context.TODO())
		if err != nil {
			c.returnError("non-existing state", http.StatusInternalServerError)
			return
		}
		requestState.DeleteRequest(stateInt)
		c.DelSession("elk-auth-state")
		proxy.ServeHTTP(c.Ctx.ResponseWriter, req)
		return
	} else if session != nil && state == nil {
		//this user has logged in, and no need to replace current request with previous request
		req := c.Ctx.Request
		//reuse the request
		proxy.ServeHTTP(c.Ctx.ResponseWriter, req)
		return
	}
}
func (c *MainController) CallbackHandler() {
	code := c.Ctx.Input.Query("code")
	state := c.Ctx.Input.Query("state")
	stateInt, err := strconv.Atoi(state)
	if err != nil {
		c.returnError(err.Error(), http.StatusBadRequest)
		return
	}

	token, err := auth.GetOAuthToken(code, state)
	if err != nil {
		c.returnError(err.Error(), http.StatusBadRequest)
		return
	}

	claims, err := auth.ParseJwtToken(token.AccessToken)
	if err != nil {
		c.returnError(err.Error(), http.StatusBadRequest)
		return
	}
	c.SetSession("username", claims.ID)
	req, err := requestState.GetRequest(stateInt)
	if err != nil {
		c.returnError(err.Error(), http.StatusBadRequest)
		return
	}

	c.Redirect(req.URL.String(), http.StatusTemporaryRedirect)
}

func (c *MainController) returnError(msg string, code int) {
	logs.Alert(msg)
	c.Data["json"] = map[string]interface{}{
		"error": msg,
	}
	c.Ctx.ResponseWriter.WriteHeader(code)
	c.ServeJSON()
}
