/** Node-runtime telemetry start-up. Opt-in: nothing is loaded unless OTEL_ENABLED=true, and a failure never stops the app. */
if (process.env.OTEL_ENABLED === "true") {
  import("./lib/telemetry-node")
    .then(({ startTelemetry }) => startTelemetry())
    .catch((error: unknown) => {
      console.error(JSON.stringify({ level: "error", event: "otel_initialization_failed", errorType: (error as Error)?.name || "Error", message: String((error as Error)?.message || "").slice(0, 200) }));
    });
}

export {};
