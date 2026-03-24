import React, { useState, useEffect, useRef } from "react";

const PROMPT = "root@voidtrace:~$";

function useTypewriter(text: string, speed = 40, startDelay = 0) {
  const [displayed, setDisplayed] = useState("");
  const [done, setDone] = useState(false);
  useEffect(() => {
    setDisplayed("");
    setDone(false);
    let i = 0;
    const t = setTimeout(() => {
      const iv = setInterval(() => {
        i++;
        setDisplayed(text.slice(0, i));
        if (i >= text.length) { clearInterval(iv); setDone(true); }
      }, speed);
      return () => clearInterval(iv);
    }, startDelay);
    return () => clearTimeout(t);
  }, [text]);
  return { displayed, done };
}

type OutputLine =
  | { type: "cmd"; text: string }
  | { type: "blank" }
  | { type: "section"; text: string }
  | { type: "row"; label: string; value: string; flag?: "ok" | "warn" | "bad" | "dim" }
  | { type: "verdict"; value: string }
  | { type: "error"; text: string };

function buildOutput(data: any): OutputLine[] {
  const lines: OutputLine[] = [];

  const flag = (v: boolean | undefined, bad = true): "ok" | "bad" | "dim" =>
    v === undefined ? "dim" : v ? (bad ? "bad" : "ok") : "ok";

  lines.push({ type: "section", text: "[+] identity & geolocation" });

  if (data.geo?.available) {
    const g = data.geo;
    lines.push({ type: "row", label: "IP", value: data.ip });
    lines.push({ type: "row", label: "HOSTNAME", value: data.rdns?.hostname || "no reverse dns" });
    lines.push({ type: "row", label: "COUNTRY", value: `${g.country || "unknown"} (${g.country_code || "??"})` });
    lines.push({ type: "row", label: "REGION", value: `${g.city || "??"}, ${g.region || "??"}` });
    lines.push({ type: "row", label: "ISP", value: g.isp || "unknown" });
    lines.push({ type: "row", label: "ORG", value: g.org || "unknown" });
  }

  if (data.flags?.available) {
    const f = data.flags;
    lines.push({ type: "row", label: "ASN", value: f.asn_number ? `AS${f.asn_number} — ${f.asn_name || ""}` : data.geo?.asn || "unknown" });
  }

  lines.push({ type: "blank" });
  lines.push({ type: "section", text: "[+] threat intelligence" });

  if (data.abuse?.available) {
    const score = data.abuse.abuse_score ?? 0;
    lines.push({
      type: "row", label: "ABUSEIPDB",
      value: `score: ${score}% — ${data.abuse.total_reports ?? 0} reports`,
      flag: score > 50 ? "bad" : score > 10 ? "warn" : "ok"
    });
    if (data.abuse.last_reported) {
      lines.push({ type: "row", label: "LAST REPORT", value: data.abuse.last_reported.split("T")[0], flag: "dim" });
    }
    if (data.abuse.usage_type) {
      lines.push({ type: "row", label: "USAGE TYPE", value: data.abuse.usage_type, flag: "dim" });
    }
  } else {
    lines.push({ type: "row", label: "ABUSEIPDB", value: "unavailable — key not set", flag: "dim" });
  }

  if (data.otx?.available) {
    const pc = data.otx.pulse_count ?? 0;
    lines.push({
      type: "row", label: "OTX PULSES",
      value: pc > 0
        ? `${pc} pulse${pc > 1 ? "s" : ""} — ${data.otx.malware_families?.join(", ") || "flagged"}`
        : "0 pulses — clean",
      flag: pc > 0 ? "bad" : "ok"
    });
  } else {
    lines.push({ type: "row", label: "OTX", value: "unavailable — key not set", flag: "dim" });
  }

  if (data.greynoise?.available) {
    const cls = data.greynoise.classification || "unknown";
    const isRiot = data.greynoise.riot;
    const name = data.greynoise.name;
    lines.push({
      type: "row", label: "GREYNOISE",
      value: isRiot
        ? `RIOT — known benign service${name ? ` (${name})` : ""}`
        : data.greynoise.noise
          ? `NOISE — ${cls}${name ? ` (${name})` : ""}`
          : `not observed`,
      flag: cls === "malicious" ? "bad" : isRiot ? "ok" : "dim"
    });
  }

  lines.push({ type: "blank" });
  lines.push({ type: "section", text: "[+] network flags" });

  if (data.flags?.available) {
    const f = data.flags;
    lines.push({ type: "row", label: "DATACENTER", value: f.is_datacenter ? "yes" : "no", flag: f.is_datacenter ? "warn" : "ok" });
    lines.push({ type: "row", label: "TOR EXIT", value: f.is_tor ? "yes" : "no", flag: flag(f.is_tor) });
    lines.push({ type: "row", label: "VPN", value: f.is_vpn ? "yes" : "no", flag: flag(f.is_vpn) });
    lines.push({ type: "row", label: "PROXY", value: f.is_proxy ? "yes" : "no", flag: flag(f.is_proxy) });
    lines.push({ type: "row", label: "ABUSER", value: f.is_abuser ? "yes" : "no", flag: flag(f.is_abuser) });
  }

  if (data.abuse?.is_tor) {
    lines.push({ type: "row", label: "TOR (ABUSE)", value: "confirmed tor exit node", flag: "bad" });
  }

  lines.push({ type: "blank" });
  lines.push({ type: "section", text: "[+] infrastructure surface" });

  if (data.shodan?.available) {
    const s = data.shodan;
    lines.push({
      type: "row", label: "OPEN PORTS",
      value: s.ports?.length ? s.ports.join(", ") : "none detected",
      flag: s.ports?.length ? "warn" : "ok"
    });
    lines.push({
      type: "row", label: "CVES",
      value: s.vulns?.length ? s.vulns.slice(0, 5).join(", ") + (s.vulns.length > 5 ? ` +${s.vulns.length - 5} more` : "") : "none detected",
      flag: s.vulns?.length ? "bad" : "ok"
    });
    lines.push({
      type: "row", label: "TAGS",
      value: s.tags?.length ? s.tags.join(", ") : "none",
      flag: "dim"
    });
    lines.push({
      type: "row", label: "CPEs",
      value: s.cpes?.length ? `${s.cpes.length} fingerprint${s.cpes.length > 1 ? "s" : ""}` : "none",
      flag: "dim"
    });
    if (s.hostnames?.length) {
      lines.push({ type: "row", label: "HOSTNAMES", value: s.hostnames.slice(0, 3).join(", "), flag: "dim" });
    }
  }

  lines.push({ type: "blank" });
  lines.push({ type: "verdict", value: data.verdict });

  return lines;
}

export default function App() {
  const [inputVal, setInputVal] = useState("");
  const [status, setStatus] = useState<"idle" | "loading" | "done" | "error">("idle");
  const [output, setOutput] = useState<OutputLine[]>([]);
  const [visibleLines, setVisibleLines] = useState(0);
  const [history, setHistory] = useState<{ ip: string; verdict: string }[]>([]);
  const [errorMsg, setErrorMsg] = useState("");
  const [showCursor, setShowCursor] = useState(true);
  const inputRef = useRef<HTMLInputElement>(null);
  const bottomRef = useRef<HTMLDivElement>(null);

  const introCmd = "voidtrace --help";
  const { displayed: typedIntro, done: introDone } = useTypewriter(introCmd, 55, 400);

  useEffect(() => {
    const t = setInterval(() => setShowCursor(c => !c), 530);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [visibleLines, status, output]);

  useEffect(() => {
    if (output.length === 0) return;
    setVisibleLines(0);
    let i = 0;
    const iv = setInterval(() => {
      i++;
      setVisibleLines(i);
      if (i >= output.length) clearInterval(iv);
    }, 35);
    return () => clearInterval(iv);
  }, [output]);

  const runLookup = async (ip: string) => {
    if (!ip.trim()) return;
    setStatus("loading");
    setOutput([]);
    setVisibleLines(0);
    setErrorMsg("");

    try {
      const apiUrl = import.meta.env.VITE_API_URL || "https://voidtrace-production.up.railway.app";
      const r = await fetch(`${apiUrl}/api/lookup`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip: ip.trim() }),
      });
      if (!r.ok) {
        const e = await r.json();
        throw new Error(e.detail || `HTTP ${r.status}`);
      }
      const data = await r.json();
      const lines = buildOutput(data);
      setOutput(lines);
      setStatus("done");
      setHistory(h => [{ ip: ip.trim(), verdict: data.verdict }, ...h.slice(0, 9)]);
    } catch (e: any) {
      setErrorMsg(e.message || "backend unreachable");
      setStatus("error");
    }
  };

  const handleKey = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key !== "Enter") return;
    const val = inputVal.trim();
    if (!val) return;
    setInputVal("");
    runLookup(val);
  };

  const verdictColor = (v: string) => {
    if (v === "MALICIOUS") return "#ff4444";
    if (v === "SUSPICIOUS") return "#ffaa00";
    return "#00ff9c";
  };

  const flagColor = (f?: string) => {
    if (f === "bad") return "#ff4444";
    if (f === "warn") return "#ffaa00";
    if (f === "dim") return "rgba(0,255,156,0.35)";
    return "#00ff9c";
  };

  return (
    <div
      className="min-h-screen bg-[#080808] text-[#00ff9c] flex flex-col"
      style={{ fontFamily: "'Share Tech Mono','Courier New',monospace" }}
      onClick={() => inputRef.current?.focus()}
    >
      {/* scanline */}
      <div className="fixed inset-0 pointer-events-none z-50" style={{
        background: "repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,255,156,0.012) 2px,rgba(0,255,156,0.012) 4px)"
      }} />

      <div className="flex-1 p-4 md:p-8 max-w-3xl mx-auto w-full">

        {/* Header */}
        <div className="flex justify-between items-center mb-5 border-b border-[#00ff9c]/10 pb-3">
          <div className="flex items-center gap-4">
            <img src="/owl.png" alt="owl logo" className="h-12 w-auto opacity-90 drop-shadow-[0_0_8px_rgba(0,255,156,0.4)]" />
            <span className="text-[10px] opacity-40">VOIDTRACE // IP INTELLIGENCE TOOL v1.0</span>
          </div>
          <span className="text-[10px] opacity-30">0TRACE SUITE</span>
        </div>

        {/* ASCII banner */}
        <pre className="text-[9px] md:text-[11px] leading-tight mb-5 opacity-50 select-none overflow-x-hidden">{
          ` ██╗   ██╗ ██████╗ ██╗██████╗ ████████╗██████╗  █████╗  ██████╗███████╗
 ██║   ██║██╔═══██╗██║██╔══██╗╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝
 ██║   ██║██║   ██║██║██║  ██║   ██║   ██████╔╝███████║██║     █████╗  
 ╚██╗ ██╔╝██║   ██║██║██║  ██║   ██║   ██╔══██╗██╔══██║██║     ██╔══╝  
  ╚████╔╝ ╚██████╔╝██║██████╔╝   ██║   ██║  ██║██║  ██║╚██████╗███████╗
   ╚═══╝   ╚═════╝ ╚═╝╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝ `}
        </pre>

        <div className="text-[10px] opacity-20 mb-6">{"─".repeat(60)}</div>

        {/* Intro typewriter */}
        <div className="text-sm mb-1">
          <span className="opacity-40">{PROMPT} </span>
          <span>{typedIntro}</span>
          {!introDone && <span className={`inline-block w-2 h-[14px] bg-[#00ff9c] ml-0.5 align-middle ${showCursor ? "opacity-100" : "opacity-0"}`} />}
        </div>

        {introDone && (
          <div className="text-xs opacity-40 mb-6 leading-relaxed">
            <div>usage: voidtrace &lt;ip_address&gt;</div>
            <div className="mt-1">example: voidtrace 8.8.8.8</div>
          </div>
        )}

        {/* Previous lookups */}
        {history.length > 0 && (
          <div className="mb-4">
            {history.map((h, i) => (
              <div key={i} className="text-xs opacity-30 flex gap-3 cursor-pointer hover:opacity-60 transition-opacity"
                onClick={() => runLookup(h.ip)}>
                <span className="opacity-60">{PROMPT}</span>
                <span>voidtrace {h.ip}</span>
                <span style={{ color: verdictColor(h.verdict) }}>[{h.verdict}]</span>
              </div>
            ))}
          </div>
        )}

        {/* Current command */}
        {status !== "idle" && (
          <div className="text-sm mb-3">
            <span className="opacity-40">{PROMPT} </span>
            <span>voidtrace {inputVal || "..."}</span>
          </div>
        )}

        {/* Loading */}
        {status === "loading" && (
          <div className="text-xs opacity-50 mb-4 animate-pulse">
            resolving target — gathering intelligence...
          </div>
        )}

        {/* Error */}
        {status === "error" && (
          <div className="text-xs mb-4" style={{ color: "#ff4444" }}>
            [!] error: {errorMsg}
          </div>
        )}

        {/* Output lines */}
        {output.slice(0, visibleLines).map((line, i) => {
          if (line.type === "blank") return <div key={i} className="h-2" />;
          if (line.type === "section") return (
            <div key={i} className="text-xs mb-1 opacity-60">{line.text}</div>
          );
          if (line.type === "row") return (
            <div key={i} className="flex text-xs mb-0.5 gap-2">
              <span className="w-24 shrink-0 opacity-40 uppercase">{line.label}</span>
              <span style={{ color: flagColor(line.flag) }}>{line.value}</span>
            </div>
          );
          if (line.type === "verdict") return (
            <div key={i} className="mt-2 mb-4">
              <div className="text-[10px] opacity-40 mb-1">{"─".repeat(40)}</div>
              <div className="text-sm flex gap-3 items-center">
                <span className="opacity-40">[!] VERDICT</span>
                <span className="font-bold tracking-widest" style={{ color: verdictColor(line.value) }}>
                  {line.value}
                </span>
              </div>
            </div>
          );
          if (line.type === "error") return (
            <div key={i} className="text-xs mb-1" style={{ color: "#ff4444" }}>{line.text}</div>
          );
          return null;
        })}

        {/* Input prompt */}
        {(status === "idle" || status === "done" || status === "error") && introDone && (
          <div className="flex items-center text-sm mt-2">
            <span className="opacity-40 mr-2 shrink-0">{PROMPT} voidtrace</span>
            <input
              ref={inputRef}
              value={inputVal}
              onChange={e => setInputVal(e.target.value)}
              onKeyDown={handleKey}
              autoFocus
              spellCheck={false}
              autoComplete="off"
              placeholder="enter ip address..."
              className="bg-transparent border-none outline-none w-full caret-[#00ff9c] placeholder:opacity-20"
              style={{ fontFamily: "'Share Tech Mono','Courier New',monospace", fontSize: "14px", color: "#00ff9c" }}
            />
            {!inputVal && (
              <span className={`inline-block w-2 h-[14px] bg-[#00ff9c] ml-0.5 ${showCursor ? "opacity-100" : "opacity-0"}`} />
            )}
          </div>
        )}

        <div ref={bottomRef} />
      </div>

      {/* Footer */}
      <div className="border-t border-[#00ff9c]/10 px-4 md:px-8 py-2 text-[9px] opacity-25 flex justify-between">
        <span className="flex items-center gap-2">
          <span className="w-1.5 h-1.5 rounded-full bg-[#00ff9c] inline-block animate-pulse" />
          UPLINK_ACTIVE
        </span>
        <span>VOIDTRACE // 0TRACE SUITE // ATHX1337</span>
      </div>
    </div>
  );
}
