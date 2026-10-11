import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Goiabada test app",
  description: "Tries each Goiabada guide against a real auth server.",
};

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
