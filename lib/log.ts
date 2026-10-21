/**
 * Server-side error logging for API routes. Logs a short context plus the error's code/name and message.
 * Never pass request bodies, headers or credentials here. Responses to the browser stay generic.
 */
export function logError(context: string, error: unknown): void {
  const e = error as { code?: string; name?: string; message?: string };
  const detail = [e?.code, e?.name].filter(Boolean).join("/") || "Error";
  console.error(`[primesec] ${context}: ${detail}: ${String(e?.message ?? error).slice(0, 300)}`);
}
