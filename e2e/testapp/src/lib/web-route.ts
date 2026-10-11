import { NextResponse } from "next/server";
import { appUrl, isWebClientKey, type WebClientKey } from "./config";
import { clientState, type ClientState } from "./session";

// Shared by the web apps' route handlers: the client the URL names, its session state, and the
// way back to its page. A POST is answered with 303, so the browser loads the page with GET.

export async function webRoute(params: Promise<{ client: string }>): Promise<
  { key: WebClientKey; state: ClientState } | { notFound: Response }
> {
  const { client: key } = await params;
  if (!isWebClientKey(key)) return { notFound: new Response("Unknown client", { status: 404 }) };
  return { key, state: await clientState(key) };
}

export function backTo(key: WebClientKey) {
  return NextResponse.redirect(`${appUrl}/${key}`, 303);
}
