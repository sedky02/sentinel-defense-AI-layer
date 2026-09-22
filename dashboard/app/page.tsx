"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import type { DecisionRecord } from "@/lib/types";
import { Sidebar } from "@/components/Sidebar";
import { TopBar } from "@/components/TopBar";
import { MetricsRow } from "@/components/MetricsRow";
import { RiskChart } from "@/components/RiskChart";
import { ControlBar, type FamilyFilter, type MethodFilter, type OutcomeFilter } from "@/components/FilterChips";
import { DecisionCard } from "@/components/DecisionCard";
import { Inspector } from "@/components/Inspector";
import { Footer } from "@/components/Footer";
import { AgentDojoPanel } from "@/components/AgentDojoPanel";
import { AttackConsole } from "@/components/AttackConsole";

const BENIGN_FAMILIES = new Set(["benign", "hard-negative"]);

type Entry = DecisionRecord & { receivedAt: number };

export default function Home() {
  const [records, setRecords] = useState<Entry[]>([]);
  const [connected, setConnected] = useState(false);
  const [paused, setPaused] = useState(false);
  const [familyFilter, setFamilyFilter] = useState<FamilyFilter>("all");
  const [outcomeFilter, setOutcomeFilter] = useState<OutcomeFilter>("all");
  const [methodFilter, setMethodFilter] = useState<MethodFilter>("all");
  const [query, setQuery] = useState("");
  const [selectedSeq, setSelectedSeq] = useState<number | null>(null);
  const [now, setNow] = useState(() => Date.now());

  const seenRef = useRef<Set<number>>(new Set());
  const pausedRef = useRef(false);
  const bufferRef = useRef<Entry[]>([]);
  pausedRef.current = paused;

  useEffect(() => {
    const source = new EventSource("/api/stream");

    source.addEventListener("connected", () => setConnected(true));
    source.addEventListener("reset", () => {
      seenRef.current = new Set();
      bufferRef.current = [];
      setRecords([]);
      setSelectedSeq(null);
    });
    source.addEventListener("decision", (event) => {
      const record = JSON.parse(event.data) as DecisionRecord;
      if (seenRef.current.has(record.seq)) return;
      seenRef.current.add(record.seq);
      const entry: Entry = { ...record, receivedAt: Date.now() };
      if (pausedRef.current) {
        bufferRef.current.push(entry);
        return;
      }
      setRecords((prev) => [...prev, entry]);
    });
    source.onerror = () => setConnected(false);

    return () => source.close();
  }, []);

  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);

  const togglePause = () => {
    setPaused((prev) => {
      const next = !prev;
      if (!next && bufferRef.current.length) {
        setRecords((records) => [...records, ...bufferRef.current]);
        bufferRef.current = [];
      }
      return next;
    });
  };

  const clearFeed = () => {
    setRecords([]);
    setSelectedSeq(null);
  };

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return records.filter((record) => {
      const family = (record.metadata?.attack_family as string) || "";
      const isBenign = BENIGN_FAMILIES.has(family);
      if (familyFilter === "benign" && !isBenign) return false;
      if (familyFilter === "attacks" && isBenign) return false;
      if (outcomeFilter !== "all" && record.outcome !== outcomeFilter) return false;
      if (methodFilter === "behavioral" && !record.reason_codes.includes("BEHAVIORAL_DIVERGENCE_DETECTED") && !record.reason_codes.includes("PARTIAL_OVERLAP_BENIGN")) return false;
      if (methodFilter === "legacy" && !record.reason_codes.includes("LEGACY_PATTERN_MATCHED") && !record.reason_codes.includes("INSTRUCTION_PATTERN_DETECTED")) return false;
      if (methodFilter === "extraction" && !(record.extracted_facts?.length ?? 0)) return false;
      if (methodFilter === "unavailable" && !record.reason_codes.some((code) => code.startsWith("BEHAVIORAL_SIGNAL_UNAVAILABLE"))) return false;
      if (q) {
        const haystack = `${record.action_type} ${record.target} ${record.reason_codes.join(" ")}`.toLowerCase();
        if (!haystack.includes(q)) return false;
      }
      return true;
    });
  }, [records, familyFilter, outcomeFilter, methodFilter, query]);

  const ordered = useMemo(() => [...filtered].reverse(), [filtered]);

  const selected = useMemo(() => {
    if (selectedSeq !== null) {
      const found = records.find((r) => r.seq === selectedSeq);
      if (found) return found;
    }
    return ordered[0] ?? null;
  }, [records, ordered, selectedSeq]);

  const recentCount = useMemo(() => records.filter((r) => now - r.receivedAt < 60_000).length, [records, now]);

  return (
    <div className="shell">
      <Sidebar connected={connected} />
      <div className="main">
        <TopBar
          connected={connected}
          paused={paused}
          onTogglePause={togglePause}
          onClear={clearFeed}
          totalCount={records.length}
          recentCount={recentCount}
        />
        <div className="content">
          <div className="top-grid">
            <MetricsRow records={records} />
            <RiskChart records={records} />
          </div>

          <ControlBar
            records={records}
            familyFilter={familyFilter}
            onFamilyFilterChange={setFamilyFilter}
            outcomeFilter={outcomeFilter}
            onOutcomeFilterChange={setOutcomeFilter}
            methodFilter={methodFilter}
            onMethodFilterChange={setMethodFilter}
            query={query}
            onQueryChange={setQuery}
          />

          <AttackConsole />

          <AgentDojoPanel />

          <div className="workspace">
            <div className="stream-col">
              <div className="stream-head">
                <div className="stream-head-left">
                  <span className="stream-head-title">Decision Stream</span>
                  <span className="stream-head-tag">Realtime</span>
                </div>
                <span className="stream-head-count">
                  Showing {ordered.length} of {records.length}
                </span>
              </div>

              {ordered.length === 0 && (
                <div className="empty-state">
                  No decisions yet. Run <code>python -m sentinel_soc_defense.demo</code> in the repo root.
                </div>
              )}

              {ordered.map((record) => (
                <DecisionCard
                  key={record.seq}
                  record={record}
                  selected={selected?.seq === record.seq}
                  onSelect={() => setSelectedSeq(record.seq)}
                />
              ))}
            </div>

            <Inspector record={selected} />
          </div>

          <Footer connected={connected} />
        </div>
      </div>
    </div>
  );
}
