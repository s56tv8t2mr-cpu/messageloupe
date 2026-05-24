"use client"

import * as React from "react"
import { useTheme } from "next-themes"
import { DropdownMenu as DropdownMenuPrimitive } from "radix-ui"
import { Monitor, Moon, Sun } from "lucide-react"

import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"

const THEMES = [
  { value: "light", label: "Light", icon: Sun },
  { value: "dark", label: "Dark", icon: Moon },
  { value: "system", label: "System", icon: Monitor },
] as const

export function ThemeSwitcher() {
  const { theme, setTheme, resolvedTheme } = useTheme()
  const [mounted, setMounted] = React.useState(false)
  React.useEffect(() => {
    const frame = window.requestAnimationFrame(() => setMounted(true))
    return () => window.cancelAnimationFrame(frame)
  }, [])

  const ActiveIcon = mounted && resolvedTheme === "dark" ? Moon : Sun

  return (
    <DropdownMenuPrimitive.Root>
      <DropdownMenuPrimitive.Trigger asChild>
        <Button
          variant="ghost"
          size="icon-sm"
          aria-label="Toggle theme"
          suppressHydrationWarning
        >
          <ActiveIcon className="size-4" aria-hidden />
        </Button>
      </DropdownMenuPrimitive.Trigger>
      <DropdownMenuPrimitive.Portal>
        <DropdownMenuPrimitive.Content
          align="end"
          sideOffset={6}
          className="border-border bg-popover text-popover-foreground z-50 min-w-[9rem] origin-(--radix-dropdown-menu-content-transform-origin) rounded-md border p-1 shadow-md data-[state=open]:animate-in data-[state=open]:fade-in-0 data-[state=open]:zoom-in-95 data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=closed]:zoom-out-95"
        >
          {THEMES.map(({ value, label, icon: Icon }) => {
            const selected = mounted && theme === value
            return (
              <DropdownMenuPrimitive.Item
                key={value}
                onSelect={() => setTheme(value)}
                aria-checked={selected}
                className={cn(
                  "focus:bg-muted focus:text-foreground relative flex cursor-pointer items-center gap-2 rounded-sm px-2 py-1.5 text-sm outline-none transition-colors select-none",
                  selected && "bg-muted text-foreground"
                )}
              >
                <Icon className="size-4" aria-hidden />
                {label}
              </DropdownMenuPrimitive.Item>
            )
          })}
        </DropdownMenuPrimitive.Content>
      </DropdownMenuPrimitive.Portal>
    </DropdownMenuPrimitive.Root>
  )
}
