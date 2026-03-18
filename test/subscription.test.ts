import { describe, expect, it } from "vitest";

import { handleRequest } from "../src/index";
import { convertInput, encodeSubscription } from "../src/subscription";

function encodeBase64(input: string): string {
  const bytes = new TextEncoder().encode(input);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

describe("subscription conversion", () => {
  it("parses raw links and re-encodes them", () => {
    const vmessPayload = encodeBase64(
      JSON.stringify({
        v: "2",
        ps: "vmess-a",
        add: "vmess.example.com",
        port: "443",
        id: "11111111-1111-1111-1111-111111111111",
        aid: "0",
        scy: "auto",
        net: "ws",
        type: "none",
        host: "cdn.example.com",
        path: "/ws",
        tls: "tls",
        sni: "vmess.example.com",
      }),
    );
    const input = [
      `vmess://${vmessPayload}`,
      "vless://22222222-2222-2222-2222-222222222222@vless.example.com:443?security=tls&type=ws&host=cdn.example.com&path=%2Fedge#vless-a",
    ].join("\n");

    const result = convertInput(input);
    expect(result.format).toBe("raw-links");
    expect(result.nodes).toHaveLength(2);

    const plain = encodeSubscription(result.nodes, false);
    expect(plain).toContain("vmess://");
    expect(plain).toContain("vless://");
  });

  it("parses Clash YAML", () => {
    const input = `
proxies:
  - name: clash-vmess
    type: vmess
    server: clash.example.com
    port: 443
    uuid: 33333333-3333-3333-3333-333333333333
    alterId: 0
    cipher: auto
    tls: true
    servername: clash.example.com
    network: ws
    ws-opts:
      path: /socket
      headers:
        Host: cdn.example.com
  - name: clash-ss
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-128-gcm
    password: pass123
`;

    const result = convertInput(input);
    expect(result.format).toBe("clash");
    expect(result.nodes).toHaveLength(2);
    expect(encodeSubscription(result.nodes, false)).toContain("ss://");
  });

  it("parses Xray JSON", () => {
    const input = JSON.stringify({
      outbounds: [
        {
          tag: "xray-vless",
          protocol: "vless",
          settings: {
            vnext: [
              {
                address: "xray.example.com",
                port: 443,
                users: [
                  {
                    id: "44444444-4444-4444-4444-444444444444",
                    flow: "xtls-rprx-vision",
                  },
                ],
              },
            ],
          },
          streamSettings: {
            network: "grpc",
            security: "tls",
            tlsSettings: {
              serverName: "xray.example.com",
            },
            grpcSettings: {
              serviceName: "grpc-service",
            },
          },
        },
      ],
    });

    const result = convertInput(input);
    expect(result.format).toBe("xray-json");
    expect(result.nodes).toHaveLength(1);
    expect(encodeSubscription(result.nodes, false)).toContain("serviceName=grpc-service");
  });

  it("parses Sing-Box JSON", () => {
    const input = JSON.stringify({
      outbounds: [
        {
          type: "trojan",
          tag: "singbox-trojan",
          server: "sing.example.com",
          server_port: 443,
          password: "secret",
          tls: {
            enabled: true,
            server_name: "sing.example.com",
          },
          transport: {
            type: "ws",
            path: "/ws",
            headers: {
              Host: "cdn.example.com",
            },
          },
        },
      ],
    });

    const result = convertInput(input);
    expect(result.format).toBe("sing-box-json");
    expect(result.nodes).toHaveLength(1);
    expect(encodeSubscription(result.nodes, false)).toContain("trojan://");
  });

  it("serves GET /sub with inline config", async () => {
    const request = new Request(
      "https://example.com/sub?config=vless%3A%2F%2F55555555-5555-5555-5555-555555555555%40demo.example.com%3A443%3Fsecurity%3Dtls%23demo&base64=false",
    );

    const response = await handleRequest(request);
    expect(response.status).toBe(200);
    expect(response.headers.get("x-sub2nodes-format")).toBe("raw-links");
    expect(await response.text()).toContain("vless://");
  });
});
