const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = 5000;

app.use(cors());
app.use(express.json());

const CSV_FILE = path.join(__dirname, "data", "results_summary.csv");

// Recent IDS events received by the backend.
// These are kept in memory for the current application session.
const idsEvents = [];
const sseClients = new Set();

function broadcastEvent(event) {
  const payload = `data: ${JSON.stringify(event)}\n\n`;

  for (const client of sseClients) {
    try {
      client.write(payload);
    } catch {
      sseClients.delete(client);
    }
  }
}

function parseCSVLine(line) {
  const values = [];
  let current = "";
  let insideQuotes = false;

  for (const char of line) {
    if (char === '"') {
      insideQuotes = !insideQuotes;
    } else if (char === "," && !insideQuotes) {
      values.push(current.trim());
      current = "";
    } else {
      current += char;
    }
  }

  values.push(current.trim());
  return values;
}

function loadResults() {
  const csv = fs.readFileSync(CSV_FILE, "utf8").trim();

  const lines = csv.split(/\r?\n/);
  const headers = parseCSVLine(lines[0]);

  return lines.slice(1).map((line) => {
    const values = parseCSVLine(line);
    const row = {};

    headers.forEach((header, index) => {
      const value = values[index] ?? "";

      if (value === "") {
        row[header] = null;
      } else if (!isNaN(value)) {
        row[header] = Number(value);
      } else {
        row[header] = value;
      }
    });

    return row;
  });
}

// Receive an IDS event
app.post("/api/events", (req, res) => {
  const {
    attackType,
    node,
    status,
    detectionTimeMs,
    mitigationTimeMs,
    message,
    address,
    eventTimeMs
  } = req.body;

  if (!attackType || node === undefined || !status) {
    return res.status(400).json({
      success: false,
      error: "attackType, node and status are required"
    });
  }

  const event = {
    id: Date.now(),
    timestamp: new Date().toISOString(),
    attackType,
    node,
    status,
    detectionTimeMs: detectionTimeMs ?? null,
    mitigationTimeMs: mitigationTimeMs ?? null,
    message: message ?? null,
    address: address ?? null,
    eventTimeMs: eventTimeMs ?? null
  };

  idsEvents.unshift(event);
  broadcastEvent(event);

  // Keep only the latest 50 events.
  if (idsEvents.length > 50) {
    idsEvents.pop();
  }

  res.status(201).json({
    success: true,
    event
  });
});

// Get recent IDS events
app.get("/api/events", (req, res) => {
  res.json({
    success: true,
    count: idsEvents.length,
    events: idsEvents
  });
});

// Real-time IDS event stream
app.get("/api/events/stream", (req, res) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");

  if (res.flushHeaders) {
    res.flushHeaders();
  }

  sseClients.add(res);

  // SSE comment; keeps the connection open without creating an IDS event.
  res.write(": connected\n\n");

  req.on("close", () => {
    sseClients.delete(res);
  });
});

// Health check
app.get("/api/health", (req, res) => {
  res.json({
    status: "OK",
    service: "Secure IoT IDS Backend",
    timestamp: new Date().toISOString()
  });
});

// All experiment results
app.get("/api/results", (req, res) => {
  try {
    const results = loadResults();

    res.json({
      success: true,
      count: results.length,
      results
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Unable to read results_summary.csv"
    });
  }
});

// Dashboard summary
app.get("/api/summary", (req, res) => {
  try {
    const results = loadResults();

    const normal = results.find((r) => r.scenario === "Normal");
    const floodingIDS = results.find(
      (r) => r.scenario === "Flooding + IDS"
    );
    const sinkholeIDS = results.find(
      (r) => r.scenario === "Sinkhole + IDS"
    );

    const totalAlerts = results.reduce(
      (sum, r) => sum + (r.ids_alerts || 0),
      0
    );

    res.json({
      success: true,
      summary: {
        totalScenarios: results.length,
        normalPDR: normal?.pdr_percent ?? null,
        floodingDetectionMs: floodingIDS?.detection_time_ms ?? null,
        floodingMitigationMs: floodingIDS?.mitigation_time_ms ?? null,
        sinkholeDetectionMs: sinkholeIDS?.detection_time_ms ?? null,
        sinkholeMitigationMs: sinkholeIDS?.mitigation_time_ms ?? null,
        totalIDSAlerts: totalAlerts
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Unable to generate dashboard summary"
    });
  }
});

// IDS alerts / attack scenarios
app.get("/api/alerts", (req, res) => {
  try {
    const results = loadResults();

    const alerts = results
      .filter((r) => r.ids_alerts > 0)
      .map((r) => ({
        scenario: r.scenario,
        attackType: r.attack_type,
        alerts: r.ids_alerts,
        drops: r.ids_drops,
        detectionTimeMs: r.detection_time_ms,
        mitigationTimeMs: r.mitigation_time_ms
      }));

    res.json({
      success: true,
      count: alerts.length,
      alerts
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Unable to read IDS alerts"
    });
  }
});

app.listen(PORT, () => {
  console.log(`Secure IoT IDS backend running on http://localhost:${PORT}`);
});
