import { CheckIcon, PaletteIcon } from "lucide-react"

import { useTheme } from "@/components/theme-provider"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { THEMES, type ThemeOption } from "@/lib/themes"

function Swatch({ option }: { option: ThemeOption }) {
  const [bg, card, primary] = option.swatch
  return (
    <span
      aria-hidden
      className="flex size-4 shrink-0 overflow-hidden rounded-full ring-1 ring-foreground/15"
      style={{ background: `linear-gradient(135deg, ${bg} 50%, ${card} 50%)` }}
    >
      <span
        className="m-auto size-1.5 rounded-full"
        style={{ background: primary }}
      />
    </span>
  )
}

export function ThemeMenu() {
  const { theme, setTheme } = useTheme()
  const modes = THEMES.filter((t) => !t.palette)
  const palettes = THEMES.filter((t) => t.palette)
  const item = (option: ThemeOption) => (
    <DropdownMenuItem key={option.id} onSelect={() => setTheme(option.id)}>
      <Swatch option={option} />
      <span className="flex-1">{option.label}</span>
      {theme === option.id ? <CheckIcon className="size-4" /> : null}
    </DropdownMenuItem>
  )
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon" aria-label="Theme">
          <PaletteIcon />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-48">
        <DropdownMenuLabel>Appearance</DropdownMenuLabel>
        {modes.map(item)}
        <DropdownMenuSeparator />
        <DropdownMenuLabel>Palettes</DropdownMenuLabel>
        {palettes.map(item)}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
