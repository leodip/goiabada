import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Goiabada test app",
  description: "Tries each Goiabada guide against a real auth server.",
};

// The app's links are plain <a>, not next/link, on purpose: a full page load makes every page
// read the session afresh, and leaves the SPA's in-memory tokens behind as a real reload would.
export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en">
      <body>
        <p>
          <a href="/">Goiabada test app</a>
        </p>
        {children}
      </body>
    </html>
  );
}
