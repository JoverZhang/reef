import { serve } from "../../lib/handler";

export const dynamic = "force-dynamic";

export function GET(request: Request) {
  return serve(request, true);
}
