function cx(...values) {
  return values.filter(Boolean).join(" ");
}

export const panelClassName =
  "relative overflow-hidden rounded-[32px] border border-vt-line bg-[linear-gradient(180deg,rgba(255,255,255,0.08),rgba(255,255,255,0.02)),var(--color-vt-panel)] p-6 shadow-[0_28px_90px_rgba(2,6,23,0.46)] backdrop-blur-[24px] before:pointer-events-none before:absolute before:inset-x-10 before:top-0 before:h-px before:bg-gradient-to-r before:from-transparent before:via-white/65 before:to-transparent after:pointer-events-none after:absolute after:-right-16 after:top-[-20%] after:h-48 after:w-48 after:rounded-full after:bg-[radial-gradient(circle,rgba(115,240,207,0.12),transparent_70%)]";

export const heroPanelClassName = `${panelClassName} p-8`;

export const primaryButtonClassName =
  "inline-flex items-center justify-center gap-2 rounded-2xl border border-white/20 bg-[linear-gradient(135deg,var(--color-vt-accent)_0%,#a5ffdb_55%,#d6fff1_100%)] px-5 py-3 font-semibold text-slate-950 shadow-[0_18px_38px_rgba(115,240,207,0.28)] transition duration-300 hover:-translate-y-0.5 hover:shadow-[0_24px_46px_rgba(115,240,207,0.34)] disabled:cursor-not-allowed disabled:opacity-60 disabled:hover:translate-y-0";

export const secondaryButtonClassName =
  "inline-flex items-center justify-center gap-2 rounded-2xl border border-vt-line bg-white/6 px-5 py-3 font-semibold text-vt-text shadow-[inset_0_1px_0_rgba(255,255,255,0.08)] transition duration-300 hover:-translate-y-0.5 hover:bg-white/10";

export const ghostButtonClassName =
  "inline-flex items-center justify-center gap-2 rounded-2xl border border-vt-line bg-transparent px-5 py-3 font-semibold text-vt-muted transition duration-300 hover:-translate-y-0.5 hover:bg-white/7 hover:text-vt-text";

const toneMap = {
  default: "bg-white/4",
  accent: "bg-[linear-gradient(180deg,rgba(121,242,192,0.12),rgba(255,255,255,0.03))]",
  danger: "bg-[linear-gradient(180deg,rgba(255,93,118,0.14),rgba(255,255,255,0.03))]",
  warning: "bg-[linear-gradient(180deg,rgba(255,185,90,0.12),rgba(255,255,255,0.03))]",
  safe: "bg-[linear-gradient(180deg,rgba(82,224,162,0.12),rgba(255,255,255,0.03))]",
};

const badgeToneMap = {
  danger: "border-[rgba(255,93,118,0.28)] bg-[rgba(255,93,118,0.14)] text-[#ffdce2]",
  warning: "border-[rgba(255,143,90,0.28)] bg-[rgba(255,143,90,0.14)] text-[#ffe7cf]",
  watch: "border-[rgba(255,185,90,0.28)] bg-[rgba(255,185,90,0.14)] text-[#ffeec0]",
  safe: "border-[rgba(82,224,162,0.28)] bg-[rgba(82,224,162,0.14)] text-[#d8fff0]",
  neutral: "border-white/10 bg-white/6 text-[#d9e3fb]",
};

export function Panel({ className, children }) {
  return <section className={cx(panelClassName, className)}>{children}</section>;
}

export function SectionHeading({ eyebrow, title, description, aside }) {
  return (
    <div className="mb-5 flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
      <div>
        {eyebrow ? (
          <div className="text-[0.72rem] font-bold uppercase tracking-[0.18em] text-vt-accent">
            {eyebrow}
          </div>
        ) : null}
        <h2 className="mt-2 text-[1.35rem] font-semibold tracking-[-0.03em]">{title}</h2>
        {description ? <p className="mt-2 max-w-3xl text-sm leading-7 text-vt-muted">{description}</p> : null}
      </div>
      {aside ? <div className="text-sm text-vt-muted">{aside}</div> : null}
    </div>
  );
}

export function MetricCard({ label, value, helper, tone = "default" }) {
  return (
    <article
      className={cx(
        "relative min-h-[132px] overflow-hidden rounded-3xl border border-vt-line p-[18px] shadow-[0_18px_40px_rgba(2,6,23,0.26)] before:pointer-events-none before:absolute before:inset-x-8 before:top-0 before:h-px before:bg-gradient-to-r before:from-transparent before:via-white/40 before:to-transparent",
        toneMap[tone] || toneMap.default,
      )}
    >
      <span className="block text-sm text-vt-muted">{label}</span>
      <strong className="mt-[18px] block text-[2.4rem] font-semibold tracking-[-0.05em]">{value}</strong>
      {helper ? <small className="mt-3 block text-[0.88rem] leading-6 text-[#d8e3fb]">{helper}</small> : null}
    </article>
  );
}

export function RiskBadge({ label, tone }) {
  return (
    <span
      className={cx(
        "inline-flex items-center justify-center rounded-full border px-3 py-2 text-[0.78rem] font-bold uppercase tracking-[0.12em]",
        badgeToneMap[tone] || badgeToneMap.neutral,
      )}
    >
      {label}
    </span>
  );
}

export function EmptyState({ title, description, action }) {
  return (
    <div className="grid place-items-start gap-3 rounded-[18px] border border-dashed border-vt-line bg-white/4 p-7 shadow-[inset_0_1px_0_rgba(255,255,255,0.05)]">
      <strong className="text-base font-semibold">{title}</strong>
      <p className="m-0 max-w-2xl text-sm leading-7 text-vt-muted">{description}</p>
      {action ? <div>{action}</div> : null}
    </div>
  );
}
