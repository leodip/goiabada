import type { Result } from "@/lib/session";

// The outcome of the last thing the user did on a page.
export function ResultBox({ result }: { result?: Result }) {
  if (!result) return null;
  return (
    <section>
      <h2 className={result.ok ? "ok" : "bad"}>{result.title}</h2>
      <p>at {new Date(result.at).toLocaleTimeString()}</p>
      <pre>{JSON.stringify(result.body, null, 2)}</pre>
    </section>
  );
}
