import "server-only";
import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { bootstrap } from "../generated/bootstrap";
import { RefreshError, redisCommand, snapshotLoader } from "./cache";
import type { Snapshot } from "./subscription";

async function compile(): Promise<Snapshot> {
  const directory = path.join(process.cwd(), "generated/runtime");
  const input = await readFile(path.join(process.cwd(), "generated/input.json"));
  return new Promise((resolve, reject) => {
    const child = spawn(path.join(directory, "python/bin/python3"),
      ["-m", "subscriptions.runtime", process.execPath], {
        cwd: directory, stdio: ["pipe", "pipe", "ignore"],
        env: { NODE_ENV: "production", PATH: path.dirname(process.execPath), PYTHONPATH: path.join(directory, "packages"),
          PYTHONDONTWRITEBYTECODE: "1", SSL_CERT_FILE: path.join(directory, "ca-bundle.pem") },
      });
    const chunks: Buffer[] = [];
    let size = 0;
    const timeout = setTimeout(() => child.kill("SIGKILL"), 180_000);
    child.stdout.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > 64 * 1024 * 1024) child.kill("SIGKILL");
      else chunks.push(chunk);
    });
    child.stdin.on("error", () => {});
    child.on("error", () => {
      clearTimeout(timeout);
      reject(new RefreshError("The subscription compiler could not start."));
    });
    child.on("close", code => {
      clearTimeout(timeout);
      try {
        const result = JSON.parse(Buffer.concat(chunks).toString());
        if (code !== 0 || !result.snapshot) {
          reject(new RefreshError(result.error ?? "Subscription compilation failed."));
        } else resolve(result.snapshot);
      } catch {
        reject(new RefreshError("Subscription compilation failed or timed out."));
      }
    });
    child.stdin.end(input);
  });
}

export const loadSnapshot = snapshotLoader({
  command: redisCommand(), compile,
  namespace: `${process.env.VERCEL_DEPLOYMENT_ID ?? "local"}:${bootstrap.buildId}`,
  historyNamespace: `${process.env.VERCEL_PROJECT_ID ?? "reef"}:${process.env.VERCEL_ENV ?? "local"}` +
    (process.env.VERCEL_ENV === "preview" ? `:${process.env.VERCEL_DEPLOYMENT_ID ?? bootstrap.buildId}` : ""),
});
