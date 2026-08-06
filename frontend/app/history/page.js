"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { motion } from "framer-motion";

import AppShell from "@/app/components/app-shell";
import ScanHistoryList from "@/app/components/scan-history-list";
import { fetchScans } from "@/lib/api";
import { normalizeScan } from "@/lib/scan-model";
import { restoreSession } from "@/lib/session";
import { useMounted } from "@/lib/use-mounted";

export default function HistoryPage() {
  const router = useRouter();
  const mounted = useMounted();
  const [user, setUser] = useState(null);
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    async function loadHistory() {
      try {
        setLoading(true);
        setError("");
        const sessionUser = await restoreSession();
        if (!sessionUser) {
          router.replace("/login");
          return;
        }

        setUser(sessionUser);
        const response = await fetchScans(sessionUser.id);
        const nextScans = Array.isArray(response?.scans)
          ? response.scans
          : Array.isArray(response)
            ? response
            : [];
        setScans(nextScans.map(normalizeScan));
      } catch (requestError) {
        setError(requestError.message);
      } finally {
        setLoading(false);
      }
    }

    loadHistory();
  }, [router]);

  if (!mounted) {
    return <main className="grid min-h-screen place-items-center text-vt-muted">Loading history...</main>;
  }

  return (
    <AppShell
      user={user}
      eyebrow="AI Malware Scanner"
      title="History"
      subtitle="Review every recorded file and URL scan from one dedicated history view."
      status={scans.length ? `${scans.length} recorded scans` : "No recorded scans"}
      actions={null}
    >
      {loading ? (
        <div className="rounded-2xl border border-white/8 bg-white/4 px-4 py-3 text-[#d6e2fb]">
          Loading scan history...
        </div>
      ) : null}
      {error ? (
        <div className="rounded-2xl border border-[rgba(255,93,118,0.2)] bg-[rgba(255,93,118,0.1)] px-4 py-3 text-[#ffd9de]">
          {error}
        </div>
      ) : null}

      {!loading && !error ? (
        <motion.section
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, ease: "easeOut" }}
        >
          <ScanHistoryList
            scans={scans}
            eyebrow="History"
            title="Recorded scans"
            description="Expand any card to inspect verdict, score, summary, and reasons."
            aside={`${scans.length} items`}
          />
        </motion.section>
      ) : null}
    </AppShell>
  );
}
