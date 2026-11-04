import type { NextApiResponse } from "next";
import { ResponseError } from "./response";
import { logError } from "./log";

const STATUS = { INVALID: 400, NOT_FOUND: 404, CONFLICT: 409, FORBIDDEN: 403, LOCKED: 423, UNAVAILABLE: 503, UPSTREAM: 502 } as const;
/** Maps our own errors to a status; anything else is logged and returned as a generic 500. */
export function respFail(res: NextApiResponse, error: unknown, context: string) {
  if (error instanceof ResponseError) return res.status(STATUS[error.code]).json({ error: error.message });
  logError(context, error);
  return res.status(500).json({ error: "The response store is unavailable." });
}
