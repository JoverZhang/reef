import { select, dump, RequestError } from "../web/lib/subscription.ts";
import { previewHtml } from "../web/lib/preview.ts";

let input = "";
for await (const chunk of process.stdin) input += chunk;
const { snapshot, query, download } = JSON.parse(input);
try {
  const before = JSON.stringify(snapshot);
  const params = new URLSearchParams(query);
  const selection = select(snapshot, params);
  const body = download ? dump(snapshot, selection) : previewHtml(selection.preview, params);
  if (JSON.stringify(snapshot) !== before) throw new Error("Request mutated the snapshot");
  process.stdout.write(JSON.stringify({ status: 200, preview: selection.preview, body }));
} catch (error) {
  if (!(error instanceof RequestError)) throw error;
  process.stdout.write(JSON.stringify({ status: error.status, body: error.message }));
}
