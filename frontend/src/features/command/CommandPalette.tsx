import Card from "@/components/ui/Card";
import CardHeader from "@/components/ui/CardHeader";
import CardContent from "@/components/ui/CardContent";

import CommandItem from "./CommandItem";
import { commandItems } from "./commandData";

export default function CommandPalette() {
  return (
    <Card>
      <CardHeader
        title="Command Palette"
        subtitle="Quick navigation and actions"
      />

      <CardContent>
        <input
          placeholder="Search..."
          className="
            mb-4
            w-full
            rounded-xl
            border
            border-slate-700
            bg-slate-800
            px-4
            py-3
            text-white
            placeholder:text-slate-500
            focus:border-cyan-500
            focus:outline-none
          "
        />

        <div className="space-y-2">
          {commandItems.map((item) => (
            <CommandItem
              key={item.id}
              icon={item.icon}
              title={item.title}
            />
          ))}
        </div>
      </CardContent>
    </Card>
  );
}