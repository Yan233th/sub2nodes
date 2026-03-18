import { parse as parseYaml } from "yaml";

export type InputFormat =
  | "raw-links"
  | "clash"
  | "xray-json"
  | "sing-box-json";

type NodeKind = "vmess" | "vless" | "trojan" | "shadowsocks";
type TransportType = "tcp" | "ws" | "grpc" | "http" | "h2";

type NodeMeta = {
  query?: Record<string, string>;
  vmess?: {
    alterId?: number;
    security?: string;
    headerType?: string;
  };
  shadowsocks?: {
    plugin?: string;
  };
};

export type Node = {
  kind: NodeKind;
  tag: string;
  host: string;
  port: number;
  auth?: {
    uuid?: string;
    password?: string;
    method?: string;
  };
  tls?: {
    enabled?: boolean;
    mode?: "tls" | "reality";
    sni?: string;
    insecure?: boolean;
    alpn?: string[];
  };
  transport?: {
    type?: TransportType;
    path?: string;
    host?: string | string[];
    headers?: Record<string, string>;
    serviceName?: string;
  };
  udp?: boolean;
  flow?: string;
  meta?: NodeMeta;
};

export type ParseResult = {
  format: InputFormat;
  nodes: Node[];
  warnings: string[];
};

type Detection = {
  format: InputFormat;
  content: string;
};

const SUPPORTED_SCHEMES = ["vmess://", "vless://", "trojan://", "ss://"];
const FORMAT_HINTS: Record<string, InputFormat> = {
  raw: "raw-links",
  links: "raw-links",
  subscription: "raw-links",
  clash: "clash",
  yaml: "clash",
  xray: "xray-json",
  v2ray: "xray-json",
  json: "xray-json",
  singbox: "sing-box-json",
  "sing-box": "sing-box-json",
};

export function convertInput(input: string, formatHint?: string): ParseResult {
  const trimmed = input.trim();
  if (!trimmed) {
    throw new Error("Input is empty.");
  }

  const hint = normalizeFormatHint(formatHint);
  const detected = detectInput(trimmed, hint);

  switch (detected.format) {
    case "raw-links":
      return parseRawLinks(detected.content);
    case "clash":
      return parseClashConfig(detected.content);
    case "xray-json":
      return parseXrayConfig(detected.content);
    case "sing-box-json":
      return parseSingBoxConfig(detected.content);
  }
}

export function renderLinks(nodes: Node[]): string {
  return nodes.map(encodeNode).join("\n");
}

export function encodeSubscription(nodes: Node[], wrapBase64 = true): string {
  const output = renderLinks(nodes);
  return wrapBase64 ? encodeBase64Text(output) : output;
}

function detectInput(input: string, forced?: InputFormat): Detection {
  if (forced === "raw-links") {
    return {
      format: "raw-links",
      content: maybeDecodeWrappedLinks(input),
    };
  }

  if (forced) {
    return {
      format: forced,
      content: input,
    };
  }

  if (containsNodeLinks(input)) {
    return {
      format: "raw-links",
      content: input,
    };
  }

  const decodedLinks = tryDecodeLinksSubscription(input);
  if (decodedLinks) {
    return {
      format: "raw-links",
      content: decodedLinks,
    };
  }

  if (looksLikeJson(input)) {
    const parsed = parseJson(input);
    if (isSingBoxShape(parsed)) {
      return {
        format: "sing-box-json",
        content: input,
      };
    }

    if (isXrayShape(parsed)) {
      return {
        format: "xray-json",
        content: input,
      };
    }

    throw new Error(
      "Unsupported JSON shape. Expected Xray/V2Ray or Sing-Box outbounds.",
    );
  }

  const yaml = parseYaml(input);
  if (isRecord(yaml) && Array.isArray(yaml.proxies)) {
    return {
      format: "clash",
      content: input,
    };
  }

  throw new Error(
    "Unsupported input. Expected raw links, Clash YAML, Xray/V2Ray JSON, or Sing-Box JSON.",
  );
}

function parseRawLinks(input: string): ParseResult {
  const nodes: Node[] = [];
  const warnings: string[] = [];

  for (const line of input.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }

    try {
      const node = parseLink(trimmed);
      if (node) {
        nodes.push(node);
      } else {
        warnings.push(`Skipped unsupported line: ${trimmed.slice(0, 32)}`);
      }
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Unknown link parse error.";
      warnings.push(`${trimmed.slice(0, 32)}: ${message}`);
    }
  }

  return {
    format: "raw-links",
    nodes,
    warnings,
  };
}

function parseClashConfig(input: string): ParseResult {
  const parsed = parseYaml(input);
  if (!isRecord(parsed) || !Array.isArray(parsed.proxies)) {
    throw new Error("Clash YAML must contain a top-level proxies array.");
  }

  const nodes: Node[] = [];
  const warnings: string[] = [];

  for (const item of parsed.proxies) {
    if (!isRecord(item)) {
      warnings.push("Skipped non-object Clash proxy entry.");
      continue;
    }

    try {
      const node = parseClashProxy(item);
      if (node) {
        nodes.push(node);
      } else {
        warnings.push(`Skipped unsupported Clash proxy type: ${String(item.type)}`);
      }
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Unknown Clash parse error.";
      warnings.push(`${stringValue(item.name) ?? "proxy"}: ${message}`);
    }
  }

  return {
    format: "clash",
    nodes,
    warnings,
  };
}

function parseXrayConfig(input: string): ParseResult {
  const parsed = parseJson(input);
  const outbounds = getXrayOutbounds(parsed);
  const nodes: Node[] = [];
  const warnings: string[] = [];

  for (const outbound of outbounds) {
    try {
      const node = parseXrayOutbound(outbound);
      if (node) {
        nodes.push(node);
      } else {
        warnings.push(
          `Skipped unsupported Xray outbound: ${stringValue(outbound.protocol) ?? "unknown"}`,
        );
      }
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Unknown Xray parse error.";
      warnings.push(`${stringValue(outbound.tag) ?? "outbound"}: ${message}`);
    }
  }

  return {
    format: "xray-json",
    nodes,
    warnings,
  };
}

function parseSingBoxConfig(input: string): ParseResult {
  const parsed = parseJson(input);
  const outbounds = getSingBoxOutbounds(parsed);
  const nodes: Node[] = [];
  const warnings: string[] = [];

  for (const outbound of outbounds) {
    try {
      const node = parseSingBoxOutbound(outbound);
      if (node) {
        nodes.push(node);
      } else {
        warnings.push(
          `Skipped unsupported Sing-Box outbound: ${stringValue(outbound.type) ?? "unknown"}`,
        );
      }
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Unknown Sing-Box parse error.";
      warnings.push(`${stringValue(outbound.tag) ?? "outbound"}: ${message}`);
    }
  }

  return {
    format: "sing-box-json",
    nodes,
    warnings,
  };
}

function parseLink(link: string): Node | null {
  if (link.startsWith("vmess://")) {
    return parseVmessLink(link);
  }

  if (link.startsWith("vless://")) {
    return parseVlessOrTrojanLink("vless", link);
  }

  if (link.startsWith("trojan://")) {
    return parseVlessOrTrojanLink("trojan", link);
  }

  if (link.startsWith("ss://")) {
    return parseShadowsocksLink(link);
  }

  return null;
}

function parseVmessLink(link: string): Node {
  const payload = link.slice("vmess://".length);
  const decoded = decodeBase64Text(payload);
  const parsed = parseJson(decoded);

  if (!isRecord(parsed)) {
    throw new Error("VMess payload is not an object.");
  }

  const host = requiredString(parsed.add, "VMess host");
  const port = requiredNumber(parsed.port, "VMess port");
  const uuid = requiredString(parsed.id, "VMess uuid");
  const network = normalizeTransportType(stringValue(parsed.net));
  const rawPath = stringValue(parsed.path);

  return {
    kind: "vmess",
    tag: stringValue(parsed.ps) ?? host,
    host,
    port,
    auth: {
      uuid,
      method: stringValue(parsed.scy) ?? "auto",
    },
    tls: buildTls({
      security: stringValue(parsed.tls),
      sni: stringValue(parsed.sni),
      alpn: csvList(parsed.alpn),
    }),
    transport: buildTransport(network, {
      path: network === "grpc" ? undefined : rawPath,
      host: stringValue(parsed.host),
      serviceName: network === "grpc" ? rawPath : undefined,
    }),
    flow: stringValue(parsed.flow),
    meta: {
      vmess: {
        alterId: numberValue(parsed.aid) ?? 0,
        security: stringValue(parsed.scy) ?? "auto",
        headerType: stringValue(parsed.type) ?? "none",
      },
    },
  };
}

function parseVlessOrTrojanLink(
  kind: "vless" | "trojan",
  link: string,
): Node {
  const url = new URL(link);
  const query = readQuery(url);
  const network = normalizeTransportType(takeQuery(query, "type"));
  const security = takeQuery(query, "security");
  const path = takeQuery(query, "path");
  const serviceName = takeQuery(query, "serviceName");
  const host = takeQuery(query, "host");
  const flow = takeQuery(query, "flow");
  const sni = takeQuery(query, "sni");
  const alpn = csvList(takeQuery(query, "alpn"));
  const insecure = parseLooseBoolean(takeQuery(query, "allowInsecure"));

  if (kind === "vless") {
    takeQuery(query, "encryption");
  }

  const auth =
    kind === "vless"
      ? { uuid: decodeURIComponent(url.username) }
      : { password: decodeURIComponent(url.username) };

  return {
    kind,
    tag: decodeHash(url.hash) ?? url.hostname,
    host: url.hostname,
    port: requiredNumber(url.port, `${kind} port`),
    auth,
    tls: buildTls({
      security,
      sni,
      insecure,
      alpn,
    }),
    transport: buildTransport(network, {
      path,
      host,
      serviceName,
    }),
    flow: flow ?? undefined,
    meta: withQueryMeta(query),
  };
}

function parseShadowsocksLink(link: string): Node {
  const withoutScheme = link.slice("ss://".length);
  const [beforeHash, hashPart = ""] = splitOnce(withoutScheme, "#");
  const [beforeQuery, queryPart = ""] = splitOnce(beforeHash, "?");
  const query = new URLSearchParams(queryPart);
  const plugin = query.get("plugin") ?? undefined;

  let credentials = "";
  let hostPart = "";

  if (beforeQuery.includes("@")) {
    const [encodedAuth, address] = splitOnce(beforeQuery, "@");
    credentials = decodeBase64Text(decodeURIComponent(encodedAuth));
    hostPart = address ?? "";
  } else {
    const decoded = decodeBase64Text(decodeURIComponent(beforeQuery));
    const [decodedCredentials, decodedHostPart] = splitOnce(decoded, "@");
    credentials = decodedCredentials;
    hostPart = decodedHostPart ?? "";
  }

  const [method, password] = splitOnce(credentials, ":");
  const [host, portText] = splitHostPort(hostPart);

  return {
    kind: "shadowsocks",
    tag: decodeHash(hashPart ? `#${hashPart}` : "") ?? host,
    host,
    port: requiredNumber(portText, "Shadowsocks port"),
    auth: {
      method: requiredString(method, "Shadowsocks method"),
      password: requiredString(password, "Shadowsocks password"),
    },
    meta:
      plugin !== undefined
        ? {
            shadowsocks: {
              plugin,
            },
          }
        : undefined,
  };
}

function parseClashProxy(proxy: Record<string, unknown>): Node | null {
  const type = normalizeProtocolType(stringValue(proxy.type));
  if (!type) {
    return null;
  }

  const host = requiredString(proxy.server, "Clash server");
  const port = requiredNumber(proxy.port, "Clash port");
  const network = normalizeTransportType(stringValue(proxy.network));
  const transport = buildTransportFromClash(proxy, network);
  const { tls, query } = buildClashTls(proxy);

  switch (type) {
    case "vmess":
      return {
        kind: "vmess",
        tag: stringValue(proxy.name) ?? host,
        host,
        port,
        auth: {
          uuid: requiredString(proxy.uuid, "Clash vmess uuid"),
          method: stringValue(proxy.cipher) ?? "auto",
        },
        tls,
        transport,
        udp: booleanValue(proxy.udp),
        meta: {
          vmess: {
            alterId: numberValue(proxy.alterId) ?? 0,
            security: stringValue(proxy.cipher) ?? "auto",
            headerType: "none",
          },
          query,
        },
      };
    case "vless":
      return {
        kind: "vless",
        tag: stringValue(proxy.name) ?? host,
        host,
        port,
        auth: {
          uuid: requiredString(proxy.uuid, "Clash vless uuid"),
        },
        tls,
        transport,
        udp: booleanValue(proxy.udp),
        flow: stringValue(proxy.flow),
        meta: withQueryMeta(query),
      };
    case "trojan":
      return {
        kind: "trojan",
        tag: stringValue(proxy.name) ?? host,
        host,
        port,
        auth: {
          password: requiredString(proxy.password, "Clash trojan password"),
        },
        tls,
        transport,
        udp: booleanValue(proxy.udp),
        meta: withQueryMeta(query),
      };
    case "shadowsocks":
      return {
        kind: "shadowsocks",
        tag: stringValue(proxy.name) ?? host,
        host,
        port,
        auth: {
          method: requiredString(proxy.cipher, "Clash Shadowsocks cipher"),
          password: requiredString(proxy.password, "Clash Shadowsocks password"),
        },
        udp: booleanValue(proxy.udp),
        meta:
          stringValue(proxy.plugin) !== undefined
            ? {
                shadowsocks: {
                  plugin: buildClashPlugin(proxy),
                },
              }
            : undefined,
      };
  }
}

function parseXrayOutbound(outbound: Record<string, unknown>): Node | null {
  const protocol = normalizeProtocolType(stringValue(outbound.protocol));
  if (!protocol) {
    return null;
  }

  const stream = recordValue(outbound.streamSettings);
  const streamInfo = buildXrayStream(stream);
  const tag = stringValue(outbound.tag);

  if (protocol === "vmess" || protocol === "vless") {
    const settings = recordValue(outbound.settings);
    const vnext = firstRecord(settings?.vnext);
    const user = firstRecord(vnext?.users);
    const host = requiredString(vnext?.address, "Xray vnext address");
    const port = requiredNumber(vnext?.port, "Xray vnext port");
    const uuid = requiredString(user?.id, "Xray user id");

    return {
      kind: protocol,
      tag: tag ?? host,
      host,
      port,
      auth: {
        uuid,
        method:
          protocol === "vmess" ? stringValue(user?.security) ?? "auto" : undefined,
      },
      tls: streamInfo.tls,
      transport: streamInfo.transport,
      flow: stringValue(user?.flow),
      meta: {
        vmess:
          protocol === "vmess"
            ? {
                alterId: numberValue(user?.alterId) ?? 0,
                security: stringValue(user?.security) ?? "auto",
                headerType: "none",
              }
            : undefined,
        query: streamInfo.query,
      },
    };
  }

  if (protocol === "trojan" || protocol === "shadowsocks") {
    const settings = recordValue(outbound.settings);
    const server = firstRecord(settings?.servers);
    const host = requiredString(server?.address, "Xray server address");
    const port = requiredNumber(server?.port, "Xray server port");

    return {
      kind: protocol,
      tag: tag ?? host,
      host,
      port,
      auth:
        protocol === "trojan"
          ? {
              password: requiredString(server?.password, "Xray trojan password"),
            }
          : {
              method: requiredString(server?.method, "Xray Shadowsocks method"),
              password: requiredString(
                server?.password,
                "Xray Shadowsocks password",
              ),
            },
      tls: protocol === "trojan" ? streamInfo.tls : undefined,
      transport: protocol === "trojan" ? streamInfo.transport : undefined,
      meta: withQueryMeta(streamInfo.query),
    };
  }

  return null;
}

function parseSingBoxOutbound(outbound: Record<string, unknown>): Node | null {
  const type = normalizeProtocolType(stringValue(outbound.type));
  if (!type) {
    return null;
  }

  const host = requiredString(outbound.server, "Sing-Box server");
  const port = requiredNumber(outbound.server_port, "Sing-Box server_port");
  const transport = buildSingBoxTransport(recordValue(outbound.transport));
  const { tls, query } = buildSingBoxTls(recordValue(outbound.tls));
  const tag = stringValue(outbound.tag) ?? host;

  switch (type) {
    case "vmess":
      return {
        kind: "vmess",
        tag,
        host,
        port,
        auth: {
          uuid: requiredString(outbound.uuid, "Sing-Box vmess uuid"),
          method: stringValue(outbound.security) ?? "auto",
        },
        tls,
        transport,
        meta: {
          vmess: {
            alterId: numberValue(outbound.alter_id) ?? 0,
            security: stringValue(outbound.security) ?? "auto",
            headerType: "none",
          },
          query,
        },
      };
    case "vless":
      return {
        kind: "vless",
        tag,
        host,
        port,
        auth: {
          uuid: requiredString(outbound.uuid, "Sing-Box vless uuid"),
        },
        tls,
        transport,
        flow: stringValue(outbound.flow),
        meta: withQueryMeta(query),
      };
    case "trojan":
      return {
        kind: "trojan",
        tag,
        host,
        port,
        auth: {
          password: requiredString(outbound.password, "Sing-Box trojan password"),
        },
        tls,
        transport,
        meta: withQueryMeta(query),
      };
    case "shadowsocks":
      return {
        kind: "shadowsocks",
        tag,
        host,
        port,
        auth: {
          method: requiredString(outbound.method, "Sing-Box Shadowsocks method"),
          password: requiredString(
            outbound.password,
            "Sing-Box Shadowsocks password",
          ),
        },
      };
  }
}

function encodeNode(node: Node): string {
  switch (node.kind) {
    case "vmess":
      return encodeVmessNode(node);
    case "vless":
      return encodeVlessOrTrojanNode("vless", node);
    case "trojan":
      return encodeVlessOrTrojanNode("trojan", node);
    case "shadowsocks":
      return encodeShadowsocksNode(node);
  }
}

function encodeVmessNode(node: Node): string {
  const transportType = node.transport?.type ?? "tcp";
  const payload = {
    v: "2",
    ps: node.tag,
    add: node.host,
    port: String(node.port),
    id: node.auth?.uuid ?? "",
    aid: String(node.meta?.vmess?.alterId ?? 0),
    scy: node.meta?.vmess?.security ?? node.auth?.method ?? "auto",
    net: transportType,
    type: node.meta?.vmess?.headerType ?? "none",
    host: transportHostString(node.transport),
    path:
      transportType === "grpc"
        ? node.transport?.serviceName ?? ""
        : node.transport?.path ?? "",
    tls: node.tls?.enabled ? "tls" : "",
    sni: node.tls?.sni ?? "",
    alpn: node.tls?.alpn?.join(",") ?? "",
    flow: node.flow ?? "",
  };

  return `vmess://${encodeBase64Text(JSON.stringify(payload))}`;
}

function encodeVlessOrTrojanNode(
  kind: "vless" | "trojan",
  node: Node,
): string {
  const auth =
    kind === "vless" ? node.auth?.uuid ?? "" : node.auth?.password ?? "";
  if (!auth) {
    throw new Error(`${kind} node is missing auth.`);
  }

  const params = new URLSearchParams();

  if (kind === "vless") {
    params.set("encryption", "none");
  }

  const security = node.tls?.mode ?? (node.tls?.enabled ? "tls" : undefined);
  if (security) {
    params.set("security", security);
  }

  const transportType = node.transport?.type;
  if (transportType && transportType !== "tcp") {
    params.set("type", transportType);
  }

  if (node.transport?.type === "grpc") {
    if (node.transport.serviceName) {
      params.set("serviceName", node.transport.serviceName);
    }
  } else if (node.transport?.path) {
    params.set("path", node.transport.path);
  }

  const host = transportHostString(node.transport);
  if (host) {
    params.set("host", host);
  }

  if (node.tls?.sni) {
    params.set("sni", node.tls.sni);
  }

  if (node.tls?.insecure) {
    params.set("allowInsecure", "1");
  }

  if (node.tls?.alpn?.length) {
    params.set("alpn", node.tls.alpn.join(","));
  }

  if (node.flow) {
    params.set("flow", node.flow);
  }

  mergeExtraQuery(params, node.meta?.query);

  const query = params.toString();
  const suffix = query ? `?${query}` : "";
  return `${kind}://${encodeURIComponent(auth)}@${node.host}:${node.port}${suffix}#${encodeURIComponent(node.tag)}`;
}

function encodeShadowsocksNode(node: Node): string {
  const method = node.auth?.method;
  const password = node.auth?.password;

  if (!method || !password) {
    throw new Error("Shadowsocks node is missing auth.");
  }

  const userInfo = encodeBase64Text(`${method}:${password}`)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
  const params = new URLSearchParams();
  const plugin = node.meta?.shadowsocks?.plugin;

  if (plugin) {
    params.set("plugin", plugin);
  }

  mergeExtraQuery(params, node.meta?.query);
  const query = params.toString();
  const suffix = query ? `?${query}` : "";
  return `ss://${userInfo}@${node.host}:${node.port}${suffix}#${encodeURIComponent(node.tag)}`;
}

function parseJson(input: string): unknown {
  try {
    return JSON.parse(input);
  } catch {
    throw new Error("Invalid JSON input.");
  }
}

function getXrayOutbounds(parsed: unknown): Record<string, unknown>[] {
  if (Array.isArray(parsed)) {
    return parsed.filter(isRecord);
  }

  if (isRecord(parsed) && Array.isArray(parsed.outbounds)) {
    return parsed.outbounds.filter(isRecord);
  }

  throw new Error("Xray/V2Ray JSON must contain an outbounds array.");
}

function getSingBoxOutbounds(parsed: unknown): Record<string, unknown>[] {
  if (isRecord(parsed) && Array.isArray(parsed.outbounds)) {
    return parsed.outbounds.filter(isRecord);
  }

  throw new Error("Sing-Box JSON must contain an outbounds array.");
}

function buildClashTls(proxy: Record<string, unknown>): {
  tls: Node["tls"];
  query?: Record<string, string>;
} {
  const reality = recordValue(proxy["reality-opts"]);
  const fingerprint = stringValue(proxy["client-fingerprint"]);
  const mode = reality ? "reality" : booleanValue(proxy.tls) ? "tls" : undefined;
  const tls = buildTls({
    security: mode,
    sni:
      stringValue(proxy.servername) ??
      stringValue(proxy.sni) ??
      stringValue(reality?.["server-name"]),
    insecure: booleanValue(proxy["skip-cert-verify"]),
    alpn: stringList(proxy.alpn),
  });

  const query: Record<string, string> = {};
  if (reality) {
    maybeSet(query, "pbk", stringValue(reality["public-key"]));
    maybeSet(query, "sid", stringValue(reality["short-id"]));
    maybeSet(query, "spx", stringValue(reality["spider-x"]));
  }
  maybeSet(query, "fp", fingerprint);

  return {
    tls,
    query: Object.keys(query).length ? query : undefined,
  };
}

function buildXrayStream(stream: Record<string, unknown> | undefined): {
  tls: Node["tls"];
  transport: Node["transport"];
  query?: Record<string, string>;
} {
  const network = normalizeTransportType(stringValue(stream?.network));
  const security = stringValue(stream?.security);
  const tlsSettings =
    recordValue(stream?.tlsSettings) ?? recordValue(stream?.xtlsSettings);
  const realitySettings = recordValue(stream?.realitySettings);
  const query: Record<string, string> = {};

  if (realitySettings) {
    maybeSet(query, "pbk", stringValue(realitySettings.publicKey));
    maybeSet(query, "sid", stringValue(realitySettings.shortId));
    maybeSet(query, "spx", stringValue(realitySettings.spiderX));
    maybeSet(query, "fp", stringValue(realitySettings.fingerprint));
  }

  const tls = buildTls({
    security: security === "reality" ? "reality" : security,
    sni:
      stringValue(realitySettings?.serverName) ??
      stringValue(tlsSettings?.serverName),
    insecure: booleanValue(tlsSettings?.allowInsecure),
    alpn: stringList(tlsSettings?.alpn),
  });

  let transport: Node["transport"];
  if (network === "ws") {
    const ws = recordValue(stream?.wsSettings);
    const headers = recordValue(ws?.headers);
    transport = buildTransport("ws", {
      path: stringValue(ws?.path),
      host: stringValue(headers?.Host) ?? stringValue(headers?.host),
      headers: toStringRecord(headers),
    });
  } else if (network === "grpc") {
    const grpc = recordValue(stream?.grpcSettings);
    transport = buildTransport("grpc", {
      serviceName:
        stringValue(grpc?.serviceName) ?? stringValue(grpc?.["service-name"]),
    });
  } else if (network === "http" || network === "h2") {
    const http = recordValue(stream?.httpSettings);
    transport = buildTransport(network, {
      path: firstString(http?.path),
      host: stringList(http?.host),
    });
  } else {
    transport = buildTransport(network);
  }

  return {
    tls,
    transport,
    query: Object.keys(query).length ? query : undefined,
  };
}

function buildSingBoxTls(tlsConfig: Record<string, unknown> | undefined): {
  tls: Node["tls"];
  query?: Record<string, string>;
} {
  const reality = recordValue(tlsConfig?.reality);
  const utls = recordValue(tlsConfig?.utls);
  const mode =
    reality && Object.keys(reality).length > 0
      ? "reality"
      : booleanValue(tlsConfig?.enabled)
        ? "tls"
        : undefined;
  const query: Record<string, string> = {};

  maybeSet(query, "pbk", stringValue(reality?.public_key));
  maybeSet(query, "sid", stringValue(reality?.short_id));
  maybeSet(query, "spx", stringValue(reality?.spider_x));
  maybeSet(query, "fp", stringValue(utls?.fingerprint));

  return {
    tls: buildTls({
      security: mode,
      sni: stringValue(tlsConfig?.server_name),
      insecure: booleanValue(tlsConfig?.insecure),
      alpn: stringList(tlsConfig?.alpn),
    }),
    query: Object.keys(query).length ? query : undefined,
  };
}

function buildSingBoxTransport(
  transportConfig: Record<string, unknown> | undefined,
): Node["transport"] {
  const type = normalizeTransportType(stringValue(transportConfig?.type));

  switch (type) {
    case "ws":
      return buildTransport("ws", {
        path: stringValue(transportConfig?.path),
        host:
          firstString(recordValue(transportConfig?.headers)?.Host) ??
          stringValue(transportConfig?.host),
        headers: toStringRecord(recordValue(transportConfig?.headers)),
      });
    case "grpc":
      return buildTransport("grpc", {
        serviceName:
          stringValue(transportConfig?.service_name) ??
          stringValue(transportConfig?.serviceName),
      });
    case "http":
    case "h2":
      return buildTransport(type, {
        path: firstString(transportConfig?.path),
        host: stringList(transportConfig?.host),
      });
    default:
      return buildTransport(type);
  }
}

function buildTransportFromClash(
  proxy: Record<string, unknown>,
  type: TransportType,
): Node["transport"] {
  switch (type) {
    case "ws": {
      const ws = recordValue(proxy["ws-opts"]);
      const headers = recordValue(ws?.headers);
      return buildTransport("ws", {
        path: stringValue(ws?.path),
        host: stringValue(headers?.Host) ?? stringValue(headers?.host),
        headers: toStringRecord(headers),
      });
    }
    case "grpc": {
      const grpc = recordValue(proxy["grpc-opts"]);
      return buildTransport("grpc", {
        serviceName:
          stringValue(grpc?.["grpc-service-name"]) ??
          stringValue(grpc?.serviceName),
      });
    }
    case "http": {
      const http = recordValue(proxy["http-opts"]);
      return buildTransport("http", {
        path: firstString(http?.path),
        host: stringList(http?.host),
      });
    }
    case "h2": {
      const h2 = recordValue(proxy["h2-opts"]);
      return buildTransport("h2", {
        path: firstString(h2?.path),
        host: stringList(h2?.host),
      });
    }
    default:
      return buildTransport(type);
  }
}

function buildClashPlugin(proxy: Record<string, unknown>): string | undefined {
  const name = stringValue(proxy.plugin);
  if (!name) {
    return undefined;
  }

  const opts = recordValue(proxy["plugin-opts"]);
  if (!opts) {
    return name;
  }

  const parts = [name];
  for (const [key, value] of Object.entries(opts)) {
    const rendered = stringValue(value) ?? (typeof value === "number" ? String(value) : undefined);
    if (rendered !== undefined) {
      parts.push(`${key}=${rendered}`);
    }
  }
  return parts.join(";");
}

function buildTls(options: {
  security?: string;
  sni?: string;
  insecure?: boolean;
  alpn?: string[];
}): Node["tls"] {
  const security = options.security;
  if (!security || security === "none" || security === "false") {
    return undefined;
  }

  return {
    enabled: true,
    mode: security === "reality" ? "reality" : "tls",
    sni: options.sni,
    insecure: options.insecure,
    alpn: options.alpn?.length ? options.alpn : undefined,
  };
}

function buildTransport(
  type: TransportType,
  overrides: Partial<Node["transport"]> = {},
): Node["transport"] {
  if (type === "tcp" && Object.keys(overrides).length === 0) {
    return undefined;
  }

  return {
    type,
    ...overrides,
  };
}

function normalizeFormatHint(value?: string): InputFormat | undefined {
  if (!value) {
    return undefined;
  }

  const normalized = FORMAT_HINTS[value.trim().toLowerCase()];
  if (!normalized) {
    throw new Error(`Unsupported format hint: ${value}`);
  }
  return normalized;
}

function normalizeProtocolType(value?: string | null): NodeKind | null {
  switch ((value ?? "").trim().toLowerCase()) {
    case "vmess":
      return "vmess";
    case "vless":
      return "vless";
    case "trojan":
      return "trojan";
    case "ss":
    case "shadowsocks":
      return "shadowsocks";
    default:
      return null;
  }
}

function normalizeTransportType(value?: string | null): TransportType {
  switch ((value ?? "").trim().toLowerCase()) {
    case "ws":
      return "ws";
    case "grpc":
      return "grpc";
    case "http":
      return "http";
    case "h2":
      return "h2";
    default:
      return "tcp";
  }
}

function containsNodeLinks(input: string): boolean {
  return input
    .split(/\r?\n/)
    .some((line) =>
      SUPPORTED_SCHEMES.some((scheme) => line.trim().startsWith(scheme)),
    );
}

function tryDecodeLinksSubscription(input: string): string | null {
  if (!/^[A-Za-z0-9+/=_\r\n-]+$/.test(input)) {
    return null;
  }

  try {
    const decoded = decodeBase64Text(input);
    return containsNodeLinks(decoded) ? decoded : null;
  } catch {
    return null;
  }
}

function maybeDecodeWrappedLinks(input: string): string {
  return tryDecodeLinksSubscription(input) ?? input;
}

function encodeBase64Text(input: string): string {
  const bytes = new TextEncoder().encode(input);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function decodeBase64Text(input: string): string {
  const normalized = padBase64(
    input.trim().replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/"),
  );
  const binary = atob(normalized);
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

function padBase64(input: string): string {
  const mod = input.length % 4;
  if (mod === 0) {
    return input;
  }
  return input + "=".repeat(4 - mod);
}

function isXrayShape(value: unknown): boolean {
  const outbounds = isRecord(value) ? value.outbounds : Array.isArray(value) ? value : null;
  return Array.isArray(outbounds) && outbounds.some((item) => isRecord(item) && typeof item.protocol === "string");
}

function isSingBoxShape(value: unknown): boolean {
  return (
    isRecord(value) &&
    Array.isArray(value.outbounds) &&
    value.outbounds.some(
      (item) => isRecord(item) && typeof item.type === "string",
    )
  );
}

function looksLikeJson(input: string): boolean {
  const first = input.trim()[0];
  return first === "{" || first === "[";
}

function readQuery(url: URL): Record<string, string> {
  const result: Record<string, string> = {};
  url.searchParams.forEach((value, key) => {
    result[key] = value;
  });
  return result;
}

function takeQuery(
  query: Record<string, string>,
  key: string,
): string | undefined {
  const value = query[key];
  delete query[key];
  return value;
}

function withQueryMeta(query?: Record<string, string>): NodeMeta | undefined {
  if (!query || Object.keys(query).length === 0) {
    return undefined;
  }
  return { query };
}

function mergeExtraQuery(
  params: URLSearchParams,
  extra?: Record<string, string>,
): void {
  if (!extra) {
    return;
  }

  for (const [key, value] of Object.entries(extra)) {
    if (!params.has(key) && value) {
      params.set(key, value);
    }
  }
}

function transportHostString(transport?: Node["transport"]): string {
  if (!transport?.host) {
    return "";
  }

  return Array.isArray(transport.host)
    ? transport.host.join(",")
    : transport.host;
}

function decodeHash(hash: string): string | undefined {
  if (!hash) {
    return undefined;
  }
  return decodeURIComponent(hash.replace(/^#/, ""));
}

function parseLooseBoolean(value?: string): boolean | undefined {
  if (value === undefined) {
    return undefined;
  }
  return ["1", "true", "yes", "on"].includes(value.toLowerCase());
}

function csvList(value: unknown): string[] | undefined {
  const text = stringValue(value);
  if (!text) {
    return undefined;
  }
  return text
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function stringList(value: unknown): string[] | undefined {
  if (typeof value === "string" && value.trim()) {
    return [value.trim()];
  }

  if (!Array.isArray(value)) {
    return undefined;
  }

  const items = value
    .map((item) => stringValue(item))
    .filter((item): item is string => Boolean(item));
  return items.length ? items : undefined;
}

function firstString(value: unknown): string | undefined {
  if (typeof value === "string") {
    return value;
  }

  if (Array.isArray(value)) {
    return stringValue(value[0]);
  }

  return undefined;
}

function requiredString(value: unknown, label: string): string {
  const text = stringValue(value);
  if (!text) {
    throw new Error(`${label} is missing.`);
  }
  return text;
}

function requiredNumber(value: unknown, label: string): number {
  const number = numberValue(value);
  if (number === undefined) {
    throw new Error(`${label} is missing.`);
  }
  return number;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function numberValue(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }

  if (typeof value === "string" && value.trim()) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : undefined;
  }

  return undefined;
}

function booleanValue(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

function recordValue(value: unknown): Record<string, unknown> | undefined {
  return isRecord(value) ? value : undefined;
}

function firstRecord(value: unknown): Record<string, unknown> | undefined {
  return Array.isArray(value) && isRecord(value[0]) ? value[0] : undefined;
}

function toStringRecord(
  value: Record<string, unknown> | undefined,
): Record<string, string> | undefined {
  if (!value) {
    return undefined;
  }

  const result: Record<string, string> = {};
  for (const [key, entry] of Object.entries(value)) {
    const rendered = stringValue(entry);
    if (rendered !== undefined) {
      result[key] = rendered;
    }
  }
  return Object.keys(result).length ? result : undefined;
}

function maybeSet(
  target: Record<string, string>,
  key: string,
  value?: string,
): void {
  if (value) {
    target[key] = value;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function splitOnce(input: string, separator: string): [string, string?] {
  const index = input.indexOf(separator);
  if (index === -1) {
    return [input];
  }
  return [input.slice(0, index), input.slice(index + separator.length)];
}

function splitHostPort(input: string): [string, string] {
  const index = input.lastIndexOf(":");
  if (index === -1) {
    throw new Error("Host:port is invalid.");
  }
  return [input.slice(0, index), input.slice(index + 1)];
}
