export function LogoMark({ size = 30 }: { size?: number }) {
  return <img src="/favicon.svg" width={size} height={size} alt="" aria-hidden="true" />;
}

export function Wordmark() {
  return <span className="flex items-center gap-2.5 font-bold tracking-tight text-[17px]">
    <LogoMark />
    <span>VPNix <span className="font-normal" style={{ color: "var(--primary-2)" }}>Create</span></span>
  </span>;
}
