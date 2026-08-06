import "./globals.css";

export const metadata = {
  title: "VulnTrack AI",
  description:
    "Multi-role security SaaS for vulnerability scanning, threat intelligence, and organization workspaces",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="vt-root" suppressHydrationWarning>
        {children}
      </body>
    </html>
  );
}
