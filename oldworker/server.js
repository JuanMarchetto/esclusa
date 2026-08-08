// Beacon for the decommission-target demo service. The gate TCP-probes port 3000;
// stopping this service out-of-band is what makes unaudited drift observable.
const http = require("node:http");

http
  .createServer((_req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ service: "oldworker", role: "decommission-target" }));
  })
  .listen(3000, "0.0.0.0", () => console.log("oldworker beacon on :3000"));
