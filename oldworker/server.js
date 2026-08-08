// Beacon for the decommission-target demo service.
//
// The gate TCP-probes port 3000 from inside the private network. `/playdead`
// closes the listener for a bounded window so the probes fail for real — the
// service genuinely stops answering, which is the only honest way to show
// drift detection from a public console. It reopens on its own, so a demo
// never leaves the project in a degraded state.
const http = require("node:http");

const PORT = Number(process.env.PORT) || 3000;
const MAX_SECONDS = 120;
const DEFAULT_SECONDS = 90;

let server = null;

function handler(req, res) {
  const json = (code, body) => {
    res.writeHead(code, { "content-type": "application/json" });
    res.end(JSON.stringify(body));
  };

  if (req.method === "POST" && req.url === "/playdead") {
    let raw = "";
    req.on("data", (c) => {
      raw += c;
      if (raw.length > 1024) req.destroy();
    });
    req.on("end", () => {
      let seconds = DEFAULT_SECONDS;
      try {
        const parsed = JSON.parse(raw || "{}");
        if (Number.isFinite(parsed.seconds)) seconds = parsed.seconds;
      } catch {
        // keep the default; a malformed body is not worth failing the demo
      }
      seconds = Math.max(5, Math.min(MAX_SECONDS, Math.floor(seconds)));
      json(200, { playingDead: true, seconds });
      // Close only after the reply is flushed, or the caller sees a reset.
      setTimeout(() => stopListening(seconds), 50);
    });
    return;
  }

  json(200, {
    service: "oldworker",
    role: "decommission-target",
    playingDead: false,
  });
}

function startListening() {
  server = http.createServer(handler);
  server.on("error", (err) => {
    // The old listening socket can linger for a moment; keep trying.
    console.log(`oldworker: listen failed (${err.code}); retrying in 1s`);
    setTimeout(startListening, 1000);
  });
  server.listen(PORT, "0.0.0.0", () => console.log(`oldworker beacon on :${PORT}`));
}

function stopListening(seconds) {
  if (!server) return;
  server.close(() => console.log("oldworker: listener closed"));
  server.closeAllConnections?.();
  server = null;
  console.log(`oldworker: playing dead for ${seconds}s`);
  setTimeout(startListening, seconds * 1000);
}

startListening();
