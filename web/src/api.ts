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

async function readResponseBody(response: Response): Promise<unknown> {
  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    return response.json();
  }
  return response.text();
}

export async function apiRequest<T>(path: string, init?: RequestInit): Promise<T> {
  const isFormData = init?.body instanceof FormData;
  const headers = new Headers(init?.headers ?? {});
  if (!isFormData && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const response = await fetch(path, {
    ...init,
    credentials: "include",
    headers,
  });

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
    return undefined as T;
  }

  return (await readResponseBody(response)) as T;
}
