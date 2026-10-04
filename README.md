# elk-auth-casdoor

[![CI](https://github.com/casdoor/elk-auth-casdoor/actions/workflows/ci.yml/badge.svg)](https://github.com/casdoor/elk-auth-casdoor/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/casdoor/elk-auth-casdoor)](https://goreportcard.com/report/github.com/casdoor/elk-auth-casdoor)
[![License](https://img.shields.io/github/license/casdoor/elk-auth-casdoor)](LICENSE)

A reverse proxy that puts [Casdoor](https://casdoor.ai) sign-in in front of Kibana (or any other web app). Users who are not signed in are sent to Casdoor; after signing in they reach Kibana through the proxy.

```
browser ──> elk-auth-casdoor (:8080) ──> Kibana (:5601)
                  │
                  └── Casdoor (OAuth 2.0 authorization code flow)
```

- The session is an HMAC-signed, `HttpOnly` cookie that expires with the Casdoor access token. The proxy keeps no state in memory, so it can be restarted or scaled out (give every instance the same `sessionSecret`).
- Every sign-in has its own random `state`, bound to the browser with a signed cookie, so the callback cannot be forged (no login CSRF).
- The access token's signature, expiry and audience are verified with the application's certificate, and only users of the configured organization are let in.
- Kibana receives `X-Forwarded-User`, `X-Forwarded-Preferred-Username` and `X-Forwarded-Email` for the signed-in user. Values sent by the client in these headers are dropped, and the proxy's own cookies are not forwarded.
- Page loads without a session are redirected to Casdoor; other requests (Kibana's API calls) get `401` instead of a cross-origin redirect.

## Quick start

1. In Casdoor, create an application for the proxy and add `<pluginEndpoint>/casdoor-auth/callback` (e.g. `http://localhost:8080/casdoor-auth/callback`) to its **Redirect URLs**.

2. Save the public certificate of the application's cert (**Certs** page in Casdoor) to `conf/token_jwt_key.pem`.

3. Edit `conf/config.json`:

    ```json
    {
      "listenAddr": ":8080",
      "pluginEndpoint": "http://localhost:8080",
      "targetEndpoint": "http://localhost:5601",
      "casdoorEndpoint": "http://localhost:8000",
      "clientId": "<client-id>",
      "clientSecret": "<client-secret>",
      "certificateFile": "conf/token_jwt_key.pem",
      "organization": "built-in",
      "application": "app-elk",
      "sessionSecret": "",
      "upstreamUsername": "",
      "upstreamPassword": ""
    }
    ```

    | Key                                     | Description                                                                                                                                                                  |
    | --------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
    | `listenAddr`                            | Address the proxy listens on, `:8080` by default                                                                                                                             |
    | `pluginEndpoint`                        | Public URL of the proxy, as users type it in the browser                                                                                                                     |
    | `targetEndpoint`                        | URL of Kibana                                                                                                                                                                |
    | `casdoorEndpoint`                       | URL of Casdoor                                                                                                                                                               |
    | `clientId`, `clientSecret`              | Client ID and secret of the Casdoor application                                                                                                                              |
    | `certificateFile`                       | Public certificate (PEM) of the application's cert                                                                                                                           |
    | `organization`                          | Organization whose users may sign in                                                                                                                                         |
    | `application`                           | Name of the Casdoor application                                                                                                                                              |
    | `sessionSecret`                         | Long random string that signs the cookies. If empty, a random one is generated at startup, which signs everybody out on every restart                                        |
    | `upstreamUsername`, `upstreamPassword`  | Optional. Sent to Kibana with HTTP basic auth, e.g. a Kibana user for everybody who signs in through Casdoor when Elasticsearch security is enabled                           |

    `CLIENT_SECRET`, `SESSION_SECRET` and `UPSTREAM_PASSWORD` in the environment override the values in the file.

4. Run it:

    ```shell
    go run . -config conf/config.json
    ```

    or with Docker:

    ```shell
    docker build -t elk-auth-casdoor .
    docker run -p 8080:8080 -v "$PWD/conf:/app/conf" -e SESSION_SECRET=<random-string> elk-auth-casdoor
    ```

5. Visit <http://localhost:8080>, sign in with Casdoor, and you see Kibana.

6. Make Kibana reachable only through the proxy (bind it to `localhost` or block its port in the firewall), otherwise users can bypass the proxy.

## Endpoints

| Path                     | Description                                                     |
| ------------------------ | --------------------------------------------------------------- |
| `/casdoor-auth/callback` | Casdoor redirects here after signing in                         |
| `/casdoor-auth/logout`   | Signs out of the proxy (the Casdoor session itself is kept)     |
| everything else          | Proxied to Kibana once signed in                                |

## Upgrading from the beego version

- The config moved from `conf/app.conf` to `conf/config.json` (`clientID` → `clientId`, `appName` → `application`, the certificate is read from `certificateFile`).
- The callback moved from `/callback` to `/casdoor-auth/callback`: update the Redirect URLs of the Casdoor application.
- Requests that arrive without a session are no longer cached and replayed after signing in: page loads are redirected to Casdoor and come back to the same URL, other requests get `401`.

## Development

```shell
go test ./...
```

## License

[Apache 2.0](LICENSE)
