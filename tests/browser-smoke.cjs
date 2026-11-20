const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const { once } = require("node:events");
const { mkdtemp, readFile, rm } = require("node:fs/promises");
const { tmpdir } = require("node:os");
const { join } = require("node:path");
const { chromium } = require("playwright");

async function originFor(server) {
  let output = "";
  const timeout = setTimeout(() => server.kill(), 10000);
  try {
    for await (const chunk of server.stdout) {
      output += chunk;
      const origin = output.match(/http:\/\/127\.0\.0\.1:\d+/)?.[0];
      if (origin) return origin;
    }
    throw new Error("The demo server did not announce its address.");
  } finally {
    clearTimeout(timeout);
  }
}

(async () => {
  const workspace = await mkdtemp(join(tmpdir(), "vera-browser-"));
  let server;
  let browser;
  try {
    server = spawn(process.env.PYTHON || "python3", [
      "-m", "aegis", "--db", join(workspace, "simulation.db"), "serve", "--host", "127.0.0.1", "--port", "0",
    ], { cwd: join(__dirname, ".."), stdio: ["ignore", "pipe", "inherit"] });
    const origin = await originFor(server);
    browser = await chromium.launch({ executablePath: process.env.CHROME_PATH, headless: true });
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
    const errors = [];
    page.on("pageerror", (error) => errors.push(String(error)));
    page.on("console", (message) => {
      if (message.type() === "error" && /CSP|policy|Cytoscape/i.test(message.text())) errors.push(message.text());
    });
    await page.goto(origin);
    await page.waitForSelector("#graph canvas");
    const replay = () => page.getByRole("button", { name: "Play scenario" }).click().then(() =>
      page.waitForFunction(() => document.querySelector('[data-action=step]').disabled &&
        !document.querySelector('[data-action=investigate]').disabled));
    const notice = (text) => page.waitForFunction((text) => document.querySelector("#notice").textContent.includes(text), text);
    const proposal = (action) => page.locator("article.proposal").filter({ has: page.getByRole("heading", { name: new RegExp(action) }) });
    const status = (card, text) => card.getByText(text, { exact: true }).waitFor();
    await page.getByRole("button", { name: "Reset" }).click();
    await page.getByLabel("Inspect a resource").selectOption("session-a");
    assert.match(await page.locator("#graph-selection").textContent(), /vm\./);
    await page.getByLabel("Show tenant ownership").check();
    await page.getByLabel("Inspect a resource").selectOption("tenant-b");
    await page.getByLabel("Show tenant ownership").uncheck();
    await page.getByRole("button", { name: "Play scenario" }).click();
    await page.getByRole("button", { name: "Pause" }).click();
    await notice("Replay paused");
    await page.getByLabel("Playback speed").selectOption("4");
    await replay();
    assert.ok(await page.locator("#attack-events li").count() > 1);
    assert.ok(await page.locator("#process li").count() > 1);
    assert.ok(await page.evaluate(() => cy.nodes(".recent-event").length > 0));
    await page.getByRole("button", { name: "Investigate", exact: true }).click();
    const broad = proposal("host.stop");
    const identity = proposal("identity.suspend");
    await broad.getByRole("button", { name: "Evaluate proposal" }).click();
    await status(broad, "DENY");
    await identity.getByRole("button", { name: "Evaluate proposal" }).click();
    await status(identity, "ALLOW");
    await identity.getByRole("button", { name: "Execute scoped action" }).click();
    await status(identity, "Verification · VERIFIED");
    await identity.getByRole("button", { name: "Retry used capability" }).click();
    await notice("DENY CONSUMED");
    await identity.getByRole("button", { name: "Re-evaluate" }).click();
    await identity.getByRole("button", { name: "Execute scoped action" }).waitFor();
    await page.getByRole("button", { name: "Change context" }).click();
    await identity.getByRole("button", { name: "Execute scoped action" }).click();
    await notice("HOLD CONTEXT CHANGED");
    const downloadPromise = page.waitForEvent("download");
    await page.getByRole("link", { name: "Export JSON" }).click();
    const download = await downloadPromise;
    const file = join(workspace, "manifest.json");
    await download.saveAs(file);
    const evidence = JSON.parse(await readFile(file, "utf-8"));
    assert.ok(evidence.events.some((event) => event.outcome === "HOLD_CONTEXT_CHANGED"));
    assert.equal(evidence.executions.length, 1);
    await page.getByText("Configured policies", { exact: true }).click();
    assert.match(await page.locator("#policies code").textContent(), /^[0-9a-f]{64}$/);

    await page.selectOption("#scenario", "secondary-scenario");
    await page.waitForFunction(() => document.querySelector("#incident").textContent.startsWith("secondary-scenario"));
    await replay();
    await page.getByRole("button", { name: "Investigate", exact: true }).click();
    const snapshot = proposal("vm.snapshot");
    await snapshot.getByRole("button", { name: "Evaluate proposal" }).click();
    await status(snapshot, "REQUIRE APPROVAL");
    await snapshot.getByRole("button", { name: "Approve", exact: true }).click();
    await status(snapshot, "Human review · incident-owner · approve");
    await snapshot.getByRole("button", { name: "Execute scoped action" }).click();
    await status(snapshot, "Verification · VERIFIED");
    await page.setViewportSize({ width: 390, height: 844 });
    await page.waitForFunction(() => document.documentElement.scrollWidth === 390);
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth), 390);
    assert.deepEqual(errors, []);
    console.log("Verified graph, replay controls, timelines, policy digest, manifest export, primary containment and drift, secondary approval, and mobile sizing.");
  } finally {
    await browser?.close();
    if (server && server.exitCode === null && server.signalCode === null && server.pid) {
      const exited = once(server, "exit");
      server.kill();
      await exited;
    }
    await rm(workspace, { recursive: true, force: true });
  }
})().catch((error) => { console.error(error); process.exitCode = 1; });
