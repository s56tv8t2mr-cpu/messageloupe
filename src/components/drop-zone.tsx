"use client"

import * as React from "react"
import { motion } from "motion/react"
import { FileUp, FileText, Mail } from "lucide-react"

import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"

const ACCEPTED_EXTENSIONS = [".eml", ".txt", ".mbox"]

interface DropZoneProps {
  onFile: (text: string, filename: string) => void
  onError: (message: string) => void
  disabled?: boolean
}

export function DropZone({ onFile, onError, disabled }: DropZoneProps) {
  const [dragActive, setDragActive] = React.useState(false)
  const inputRef = React.useRef<HTMLInputElement>(null)

  const handleFile = React.useCallback(
    (file: File) => {
      const lowerName = file.name.toLowerCase()
      const isAccepted =
        ACCEPTED_EXTENSIONS.some((ext) => lowerName.endsWith(ext)) ||
        file.type === "message/rfc822" ||
        file.type === "text/plain" ||
        file.type === ""
      if (!isAccepted) {
        onError(
          `${file.name} doesn't look like a saved email. Try a .eml file, or switch to "Paste headers."`,
        )
        return
      }

      if (file.size > 25 * 1024 * 1024) {
        onError("That file is over 25 MB. Are you sure it's a saved email?")
        return
      }

      const reader = new FileReader()
      reader.onload = () => {
        const text = typeof reader.result === "string" ? reader.result : ""
        if (!text.trim()) {
          onError("That file appears to be empty.")
          return
        }
        onFile(text, file.name)
      }
      reader.onerror = () => {
        onError("Couldn't read that file. Try saving it again.")
      }
      reader.readAsText(file)
    },
    [onFile, onError],
  )

  const onDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    setDragActive(false)
    if (disabled) return
    const file = e.dataTransfer.files?.[0]
    if (file) handleFile(file)
  }

  const onChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) handleFile(file)
    e.target.value = ""
  }

  const Icon = dragActive ? FileText : FileUp

  return (
    <div
      data-drag-active={dragActive || undefined}
      onDragEnter={(e) => {
        e.preventDefault()
        if (!disabled) setDragActive(true)
      }}
      onDragOver={(e) => {
        e.preventDefault()
        if (!disabled) setDragActive(true)
      }}
      onDragLeave={(e) => {
        e.preventDefault()
        setDragActive(false)
      }}
      onDrop={onDrop}
      onClick={() => !disabled && inputRef.current?.click()}
      role="button"
      tabIndex={disabled ? -1 : 0}
      onKeyDown={(e) => {
        if (disabled) return
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault()
          inputRef.current?.click()
        }
      }}
      aria-label="Drop a saved email here, or click to browse"
      className={cn(
        "group relative cursor-pointer overflow-hidden rounded-xl border border-dashed outline-none transition-all duration-200",
        "focus-visible:ring-ring focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-offset-background",
        dragActive
          ? "border-primary/70 bg-primary/[0.05] scale-[1.005]"
          : "border-border hover:border-primary/50 bg-card hover:bg-primary/[0.02]",
        disabled && "pointer-events-none opacity-60",
      )}
    >
      <div
        aria-hidden
        className={cn(
          "pointer-events-none absolute inset-0 opacity-0 transition-opacity duration-300",
          dragActive
            ? "opacity-100"
            : "group-hover:opacity-60",
        )}
        style={{
          background:
            "radial-gradient(ellipse at center, color-mix(in oklch, var(--primary) 12%, transparent), transparent 70%)",
        }}
      />

      <div className="relative flex flex-col items-center justify-center gap-3 px-6 py-12 text-center">
        <motion.div
          aria-hidden
          animate={
            dragActive ? { scale: 1.06 } : { scale: 1 }
          }
          transition={{ type: "spring", stiffness: 260, damping: 22 }}
          className={cn(
            "flex size-14 items-center justify-center rounded-full transition-colors duration-200",
            dragActive
              ? "bg-primary/15 text-primary ring-primary/25 ring-4"
              : "bg-muted text-muted-foreground group-hover:bg-primary/10 group-hover:text-primary",
          )}
        >
          <Icon className="size-6" aria-hidden />
        </motion.div>

        <div className="flex flex-col items-center gap-2">
          <p className="text-foreground text-lg font-semibold tracking-tight">
            {dragActive ? "Drop it here" : "Drop a saved email here"}
          </p>
          <p className="text-muted-foreground max-w-md text-base leading-relaxed">
            <span className="font-mono text-sm">.eml</span> or{" "}
            <span className="font-mono text-sm">.txt</span> with raw headers. Up to
            25 MB. Nothing leaves your browser.
          </p>
        </div>

        <input
          ref={inputRef}
          type="file"
          accept=".eml,.txt,.mbox,message/rfc822,text/plain"
          className="hidden"
          onChange={onChange}
          disabled={disabled}
        />
        <Button
          variant="outline"
          onClick={(e) => {
            e.stopPropagation()
            inputRef.current?.click()
          }}
          disabled={disabled}
          className="mt-1"
        >
          <Mail data-icon="inline-start" />
          Browse files
        </Button>
      </div>
    </div>
  )
}
