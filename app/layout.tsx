import "./globals.css";

export const metadata = {
  title: "AegisAI",
  description: "AI Powered Web Security Scanner"
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="fr">
      <body>{children}</body>
    </html>
  );
}
