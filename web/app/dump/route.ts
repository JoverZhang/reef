import { serve } from "../../lib/handler";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";
export const maxDuration = 300;

export function GET(request: Request) {
  return serve(request, true);
}
