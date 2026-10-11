import { apiUrl } from "./config";

// Calls the API with a bearer token, as an app or a service would, and reports what came back.
export async function callApi(accessToken: string) {
  try {
    const response = await fetch(apiUrl, { headers: { authorization: `Bearer ${accessToken}` } });
    const text = await response.text();
    let body: unknown = text;
    try {
      body = JSON.parse(text);
    } catch {}
    return {
      status: response.status,
      www_authenticate: response.headers.get("www-authenticate") ?? undefined,
      body,
    };
  } catch (error) {
    return { status: 0, error: error instanceof Error ? error.message : String(error) };
  }
}
