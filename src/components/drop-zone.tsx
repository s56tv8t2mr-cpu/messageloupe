"use client"

import * as React from "react"
import { FileUp, FileText } from "lucide-react"

import {
  Empty,
  EmptyContent,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"
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
      className={cn(
        "rounded-xl border border-dashed transition-all",
        dragActive
          ? "border-primary/60 bg-primary/[0.04] scale-[1.005]"
          : "border-border/60 bg-card/40",
        disabled && "pointer-events-none opacity-60",
      )}
    >
      <Empty className="border-0 bg-transparent py-12">
        <EmptyHeader>
          <EmptyMedia variant="icon" className="bg-muted size-12 [&_svg:not([class*='size-'])]:size-5">
            {dragActive ? <FileText aria-hidden /> : <FileUp aria-hidden />}
          </EmptyMedia>
          <EmptyTitle className="text-base">
            {dragActive ? "Drop it here" : "Drop a saved email here"}
          </EmptyTitle>
          <EmptyDescription>
            <span className="font-mono text-xs">.eml</span> or{" "}
            <span className="font-mono text-xs">.txt</span> with raw headers. Up to
            25 MB. Nothing leaves your browser.
          </EmptyDescription>
        </EmptyHeader>
        <EmptyContent>
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
            size="sm"
            onClick={() => inputRef.current?.click()}
            disabled={disabled}
          >
            Browse files
          </Button>
        </EmptyContent>
      </Empty>
    </div>
  )
}
