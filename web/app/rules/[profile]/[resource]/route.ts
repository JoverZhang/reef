import { rules } from "../../../../lib/handler";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";
export const maxDuration = 300;

export async function GET(request: Request, context: { params: Promise<{ profile: string; resource: string }> }) {
  const { profile, resource } = await context.params;
  return rules(request, `${profile}/${resource}`);
}
