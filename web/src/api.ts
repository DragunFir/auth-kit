import type { ApiErrorShape } from "./types";

export class ApiError extends Error {
  status: number;
  errorCode: string | null;
  details: Array<Record<string, unknown>> | null;

  constructor(
    message: string,
    status: number,
    errorCode: string | null = null,
    details: Array<Record<string, unknown>> | null = null,
  ) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.errorCode = errorCode;
    this.details = details;
  }
}

type CsrfResponse = {
  csrf_token: string;
};

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
let csrfToken: string | null = null;
let csrfRequest: Promise<string> | null = null;

async function readResponseBody(response: Response): Promise<unknown> {
  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    return response.json();
  }
  return response.text();
}

async function fetchCsrfToken(): Promise<string> {
  const response = await fetch("/api/auth/csrf", {
    credentials: "include",
    headers: {
      Accept: "application/json",
    },
  });
  if (!response.ok) {
    throw new ApiError(`Request failed with ${response.status}`, response.status);
  }
  const body = (await readResponseBody(response)) as CsrfResponse;
  csrfToken = body.csrf_token;
  return csrfToken;
}

async function ensureCsrfToken(): Promise<string> {
  if (csrfToken) {
    return csrfToken;
  }
  if (!csrfRequest) {
    csrfRequest = fetchCsrfToken().finally(() => {
      csrfRequest = null;
    });
  }
  return csrfRequest;
}

function shouldAttachCsrf(path: string, init?: RequestInit): boolean {
  const method = (init?.method ?? "GET").toUpperCase();
  return !SAFE_METHODS.has(method) && path !== "/api/auth/csrf";
}

function resetCsrfToken(): void {
  csrfToken = null;
}

async function performRequest(path: string, init?: RequestInit): Promise<Response> {
  const isFormData = init?.body instanceof FormData;
  const headers = new Headers(init?.headers ?? {});
  if (!isFormData && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  if (shouldAttachCsrf(path, init)) {
    headers.set("X-CSRF-Token", await ensureCsrfToken());
  }

  return fetch(path, {
    ...init,
    credentials: "include",
    headers,
  });
}

export async function apiRequest<T>(path: string, init?: RequestInit): Promise<T> {
  let response = await performRequest(path, init);
  if (response.status === 403) {
    const body = (await readResponseBody(response)) as ApiErrorShape | string;
    if (typeof body !== "string" && body?.error_code === "csrf_invalid" && shouldAttachCsrf(path, init)) {
      resetCsrfToken();
      response = await performRequest(path, init);
    } else {
      if (typeof body === "string") {
        throw new ApiError(body || `Request failed with ${response.status}`, response.status);
      }
      const details = Array.isArray(body?.details)
        ? (body.details as Array<Record<string, unknown>>)
        : null;
      throw new ApiError(body?.message || `Request failed with ${response.status}`, response.status, body?.error_code ?? null, details);
    }
  }

  if (!response.ok) {
    const body = (await readResponseBody(response)) as ApiErrorShape | string;
    if (typeof body === "string") {
      throw new ApiError(body || `Request failed with ${response.status}`, response.status);
    }
    const details = Array.isArray(body?.details)
      ? (body.details as Array<Record<string, unknown>>)
      : null;
    const baseMessage =
      typeof body?.message === "string"
        ? body.message
        : typeof body?.detail === "string"
          ? body.detail
          : `Request failed with ${response.status}`;
    const detailMessage =
      body?.error_code === "validation_error" && details?.[0] && typeof details[0].msg === "string"
        ? `${baseMessage} ${details[0].msg}`
        : baseMessage;
    throw new ApiError(detailMessage, response.status, body?.error_code ?? null, details);
  }

  if (response.status === 204) {
    if (path === "/api/auth/sessions/current") {
      resetCsrfToken();
    }
    return undefined as T;
  }

  if (path === "/api/auth/logout") {
    resetCsrfToken();
  }

  return (await readResponseBody(response)) as T;
}
