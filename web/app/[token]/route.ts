import { subscriptions } from "@/generated/subscriptions";

export const dynamic = "force-dynamic";

type RouteContext = {
  params: Promise<{
    token: string;
  }>;
};

const headers = {
  "Cache-Control": "no-store",
  "X-Robots-Tag": "noindex, nofollow, noarchive",
};

export async function GET(_request: Request, context: RouteContext) {
  const { token } = await context.params;
  const subscription = subscriptions.find((item) => item.token === token);

  if (!subscription) {
    return new Response("Not found", {
      status: 404,
      headers,
    });
  }

  return new Response(subscription.body, {
    status: 200,
    headers: {
      ...headers,
      "Content-Type": subscription.contentType,
    },
  });
}
