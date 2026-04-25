import { Outlet, Link, createRootRoute, HeadContent, Scripts } from "@tanstack/react-router";
import { Toaster } from "sonner";

import appCss from "../styles.css?url";

function NotFoundComponent() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-background px-4">
      <div className="brut-border brut-shadow bg-white p-10 text-center max-w-md">
        <h1 className="font-display text-7xl font-bold">404</h1>
        <h2 className="mt-4 text-xl font-display font-bold uppercase tracking-wider">Page Not Found</h2>
        <p className="mt-2 text-sm font-mono text-muted-foreground">
          The page you're looking for doesn't exist.
        </p>
        <div className="mt-6">
          <Link
            to="/"
            className="brut-border brut-shadow brut-press inline-flex items-center justify-center bg-brut-yellow px-4 py-2 font-display font-bold uppercase tracking-wider text-sm text-black"
          >
            Go Home
          </Link>
        </div>
      </div>
    </div>
  );
}

export const Route = createRootRoute({
  head: () => ({
    meta: [
      { charSet: "utf-8" },
      { name: "viewport", content: "width=device-width, initial-scale=1" },
      { title: "Project Phoenix — Incident Forensics" },
      { name: "description", content: "Neo brutalist cybersecurity log analysis & incident forensics dashboard." },
      { name: "author", content: "Phoenix" },
      { property: "og:title", content: "Project Phoenix" },
      { property: "og:description", content: "Incident forensics for log analysis and attack visualization." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
      { name: "twitter:site", content: "@Lovable" },
    ],
    links: [
      {
        rel: "stylesheet",
        href: appCss,
      },
    ],
  }),
  shellComponent: RootShell,
  component: RootComponent,
  notFoundComponent: NotFoundComponent,
});

function RootShell({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head>
        <HeadContent />
      </head>
      <body>
        {children}
        <Scripts />
      </body>
    </html>
  );
}

function RootComponent() {
  return (
    <>
      <Outlet />
      <Toaster
        position="top-right"
        toastOptions={{
          style: {
            border: "3px solid #000",
            borderRadius: "4px",
            boxShadow: "4px 4px 0px 0px #000",
            fontFamily: "Space Grotesk, sans-serif",
            fontWeight: 700,
            textTransform: "uppercase",
            letterSpacing: "0.05em",
          },
        }}
      />
    </>
  );
}
