import { convertInput, encodeSubscription } from "./subscription";

type HttpError = Error & { status?: number };

export default {
  fetch: handleRequest,
};

export async function handleRequest(request: Request): Promise<Response> {
  const url = new URL(request.url);

  if (url.pathname === "/") {
    return new Response(renderHome(url), {
      headers: {
        "content-type": "text/html; charset=utf-8",
      },
    });
  }

  if (url.pathname !== "/sub") {
    return errorResponse(404, "Not found.");
  }

  try {
    const source = await resolveSource(url);
    const shouldWrapBase64 = parseBoolean(url.searchParams.get("base64"), true);
    const result = convertInput(source, url.searchParams.get("format") ?? undefined);

    if (result.nodes.length === 0) {
      return errorResponse(
        422,
        result.warnings[0] ?? "No supported nodes were produced.",
      );
    }

    const body = encodeSubscription(result.nodes, shouldWrapBase64);
    return new Response(body, {
      headers: {
        "content-type": "text/plain; charset=utf-8",
        "cache-control": "no-store",
        "x-sub2nodes-format": result.format,
        "x-sub2nodes-count": String(result.nodes.length),
        "x-sub2nodes-warnings": String(result.warnings.length),
      },
    });
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "Unexpected conversion error.";
    const status =
      typeof (error as HttpError).status === "number"
        ? (error as HttpError).status!
        : 400;
    return errorResponse(status, message);
  }
}

async function resolveSource(url: URL): Promise<string> {
  const remoteUrl = url.searchParams.get("url");
  if (!remoteUrl) {
    throw withStatus(new Error("Provide ?url=."), 400);
  }

  let target: URL;
  try {
    target = new URL(remoteUrl);
  } catch {
    throw withStatus(new Error("The url parameter must be a valid absolute URL."), 400);
  }

  const response = await fetch(target.toString());
  if (!response.ok) {
    throw withStatus(
      new Error(`Upstream fetch failed with status ${response.status}.`),
      502,
    );
  }

  return await response.text();
}

function parseBoolean(value: string | null, defaultValue: boolean): boolean {
  if (value === null) {
    return defaultValue;
  }

  return !["0", "false", "no", "off"].includes(value.toLowerCase());
}

function errorResponse(status: number, error: string): Response {
  return new Response(JSON.stringify({ error }), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

function withStatus(error: Error, status: number): HttpError {
  (error as HttpError).status = status;
  return error as HttpError;
}

function renderHome(url: URL): string {
  const base = `${url.origin}/sub`;
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>sub2nodes</title>
    <style>
      :root {
        color-scheme: light;
        font-family: "IBM Plex Sans", "Noto Sans", sans-serif;
      }
      body {
        margin: 0;
        background: #f5f1e8;
        color: #1c1812;
      }
      main {
        max-width: 760px;
        margin: 0 auto;
        padding: 32px 20px 48px;
      }
      h1 {
        margin: 0 0 8px;
        font-size: 2rem;
      }
      p {
        margin: 0 0 20px;
        line-height: 1.6;
      }
      .panel {
        background: #fffdf8;
        border: 1px solid #d7cbb8;
        padding: 18px;
      }
      label {
        display: block;
        font-weight: 600;
        margin: 14px 0 6px;
      }
      input,
      select,
      button {
        width: 100%;
        box-sizing: border-box;
        font: inherit;
      }
      input,
      select {
        border: 1px solid #b5a48a;
        padding: 10px 12px;
        background: #fff;
      }
      .row {
        display: grid;
        grid-template-columns: 1fr 140px;
        gap: 12px;
      }
      button {
        border: 0;
        padding: 12px 14px;
        background: #202c39;
        color: #fff;
        cursor: pointer;
        margin-top: 14px;
      }
      .actions {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 12px;
      }
      .muted {
        color: #5e5548;
        font-size: 0.95rem;
      }
    </style>
  </head>
  <body>
    <main>
      <h1>sub2nodes</h1>
      <p>Minimal converter for raw links, Clash YAML, Xray/V2Ray JSON, and Sing-Box JSON.</p>
      <div class="panel">
        <label for="url">Remote URL</label>
        <input id="url" placeholder="https://example.com/subscription" />

        <div class="row">
          <div>
            <label for="format">Format hint</label>
            <select id="format">
              <option value="">auto</option>
              <option value="raw">raw-links</option>
              <option value="clash">clash</option>
              <option value="xray">xray-json</option>
              <option value="sing-box">sing-box-json</option>
            </select>
          </div>
          <div>
            <label for="base64">Wrap output</label>
            <select id="base64">
              <option value="true">base64</option>
              <option value="false">plain</option>
            </select>
          </div>
        </div>

        <button id="generate" type="button">Generate link</button>

        <label for="result">Generated link</label>
        <input id="result" readonly />
        <p class="muted">The generated link converts your remote source on demand.</p>

        <div class="actions">
          <button id="copy" type="button">Copy</button>
          <button id="preview" type="button">Preview</button>
        </div>
      </div>
    </main>
    <script>
      const endpoint = ${JSON.stringify(base)};
      const urlInput = document.getElementById("url");
      const formatInput = document.getElementById("format");
      const base64Input = document.getElementById("base64");
      const resultInput = document.getElementById("result");

      function buildLink() {
        const target = new URL(endpoint);
        if (urlInput.value.trim()) {
          target.searchParams.set("url", urlInput.value.trim());
        }
        if (formatInput.value) {
          target.searchParams.set("format", formatInput.value);
        }
        target.searchParams.set("base64", base64Input.value);
        resultInput.value = target.toString();
      }

      document.getElementById("generate").addEventListener("click", buildLink);
      document.getElementById("copy").addEventListener("click", async () => {
        buildLink();
        if (resultInput.value) {
          await navigator.clipboard.writeText(resultInput.value);
        }
      });
      document.getElementById("preview").addEventListener("click", () => {
        buildLink();
        if (resultInput.value) {
          window.open(resultInput.value, "_blank", "noopener,noreferrer");
        }
      });
    </script>
  </body>
</html>`;
}
