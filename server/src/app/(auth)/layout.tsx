export default function AuthLayout({ children }: { children: React.ReactNode }) {
  return (
    <main className="flex min-h-screen items-center justify-center p-4">
      <div className="w-full max-w-sm rounded-lg border border-line bg-panel p-6">
        <h1 className="mb-4 text-lg font-semibold">minisoc2</h1>
        {children}
      </div>
    </main>
  );
}
