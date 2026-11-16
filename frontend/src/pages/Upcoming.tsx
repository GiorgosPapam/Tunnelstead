import { Construction } from "lucide-react";
import { Empty } from "../components/ui";

// Shown for sections whose features are scheduled for a later phase: an honest status, never fake controls.
export default function Upcoming({ title, phase, text }: { title: string; phase: number; text: string }) {
  return <>
    <h1 className="text-2xl font-semibold tracking-tight m-0 mb-1">{title}</h1>
    <p className="muted mt-0 mb-6">Not available yet</p>
    <Empty icon={<Construction size={22} />} title={`Arrives in development phase ${phase}`} text={text} />
  </>;
}
