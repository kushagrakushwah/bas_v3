import { NextRequest, NextResponse } from "next/server";
import { getToken } from "next-auth/jwt";

const API_BASE = process.env.INTERNAL_API_URL || "http://bas-engine:8000";

// C3 fix: strict allowlist of paths the proxy will forward
const ALLOWED_PATH_PREFIXES = [
  "api/v1/modules",
  "api/v1/simulations",
  "api/v1/results",
  "api/v1/events",
  "api/v1/infrastructure",
  "api/v1/integrations",
  "api/v1/metrics",
  "api/v1/replay",
  "api/v1/recon",
  "api/v1/health",
  "api/v1/ws",
];

// H4 fix: only forward safe, non-sensitive headers
const SAFE_HEADERS_TO_FORWARD = new Set([
  "content-type",
  "accept",
  "accept-language",
  "cache-control",
]);

async function proxy(
  request: NextRequest,
  { params }: { params: { path: string[] } }
) {
  const pathSegments = params.path;

  // C3 fix: reject path traversal attempts
  if (pathSegments.some((segment) => segment === ".." || segment === ".")) {
    return NextResponse.json(
      { error: "Path traversal is not permitted." },
      { status: 400 }
    );
  }

  const joinedPath = pathSegments.join("/");

  // C3 fix: allowlist check
  const isAllowed = ALLOWED_PATH_PREFIXES.some((prefix) =>
    joinedPath.startsWith(prefix)
  );
  if (!isAllowed) {
    return NextResponse.json(
      { error: "Path not permitted by proxy policy." },
      { status: 403 }
    );
  }

  const search = request.nextUrl.search;
  const url = `${API_BASE}/${joinedPath}${search}`;

  // H4 fix: build a clean header set — only forward safe headers
  const forwardHeaders = new Headers();
  forwardHeaders.set("X-API-Key", process.env.API_KEY || "");
  
  const token = await getToken({ req: request as any });
  if (token && token.backendToken) {
    forwardHeaders.set("Authorization", `Bearer ${token.backendToken}`);
  }
  
  forwardHeaders.set("Content-Type", "application/json");

  request.headers.forEach((value, key) => {
    if (SAFE_HEADERS_TO_FORWARD.has(key.toLowerCase())) {
      forwardHeaders.set(key, value);
    }
  });

  // L6 fix: add request timeout via AbortController
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 30000);

  try {
    const response = await fetch(url, {
      method: request.method,
      headers: forwardHeaders,
      body:
        request.method !== "GET" && request.method !== "HEAD"
          ? await request.arrayBuffer()
          : undefined,
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    const contentType =
      response.headers.get("Content-Type") || "application/json";

    return new NextResponse(response.body, {
      status: response.status,
      headers: {
        "Content-Type": contentType,
      },
    });
  } catch (error: any) {
    clearTimeout(timeoutId);
    if (error?.name === "AbortError") {
      return NextResponse.json(
        { error: "Backend request timed out." },
        { status: 504 }
      );
    }
    // Surface the actual error message in development
    const detail =
      process.env.NODE_ENV === "development" ? String(error) : "Proxy error";
    return NextResponse.json({ error: detail }, { status: 502 });
  }
}

export const GET = proxy;
export const POST = proxy;
export const PUT = proxy;
export const DELETE = proxy;
export const PATCH = proxy;
