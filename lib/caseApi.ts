import type { NextApiResponse } from "next";
import { CaseError } from "./cases";
import { InvestigateError } from "./investigate";
import { ResponseError } from "./response";
import { logError } from "./log";

const CASE = { INVALID: 400, NOT_FOUND: 404, CONFLICT: 409, LIMIT: 409 } as const;
const RESP = { INVALID: 400, NOT_FOUND: 404, CONFLICT: 409, FORBIDDEN: 403, LOCKED: 423, UNAVAILABLE: 503, UPSTREAM: 502 } as const;
/** Maps our own errors to a status; anything else is logged and returned as a generic 500. */
export function caseFail(res: NextApiResponse, error: unknown, context: string) {
  if (error instanceof CaseError) return res.status(CASE[error.code]).json({ error: error.message });
  if (error instanceof ResponseError) return res.status(RESP[error.code]).json({ error: error.message });
  if (error instanceof InvestigateError) return res.status(error.code === "INVALID" ? 400 : error.code === "NOT_FOUND" ? 404 : 409).json({ error: error.message });
  logError(context, error);
  return res.status(500).json({ error: "The case store is unavailable." });
}
