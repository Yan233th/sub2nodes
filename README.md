# sub2nodes

Convert a remote source into pure node subscriptions for `v2rayN`-style clients.

## Deploy to Cloudflare Workers

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/Yan233th/sub2nodes)

Deploy it, then use your `*.workers.dev` URL as the service base.

## API

### `GET /`

Small homepage for generating a conversion link.

### `GET /sub`

Convert a remote source into a node subscription.

Query parameters:

- `url` required. Remote source URL.
- `base64` optional. Default is `true`. Use `false` for plain node links.
- `format` optional. Debug-only hint: `raw`, `clash`, `xray`, `sing-box`.

Behavior:

- Detects raw links, Clash YAML, Xray/V2Ray JSON, and Sing-Box JSON.
- Converts supported nodes to `vmess://`, `vless://`, `trojan://`, and `ss://`.
- Returns base64 text by default.

Example:

```text
/sub?url=https%3A%2F%2Fexample.com%2Fsubscription&base64=true
```

Example with a format hint:

```text
/sub?url=https%3A%2F%2Fexample.com%2Fconfig.yaml&format=clash&base64=false
```
