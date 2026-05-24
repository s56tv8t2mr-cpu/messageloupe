"use client"

import * as React from "react"
import { ScanLine } from "lucide-react"

import { Textarea } from "@/components/ui/textarea"
import { Button } from "@/components/ui/button"
import { Label } from "@/components/ui/label"

interface PasteHeadersProps {
  onSubmit: (text: string) => void
  disabled?: boolean
}

export function PasteHeaders({ onSubmit, disabled }: PasteHeadersProps) {
  const [text, setText] = React.useState("")
  const trimmed = text.trim()
  const charCount = text.length
  const ready = trimmed.length > 50

  return (
    <div className="rounded-xl border border-dashed border-border/60 bg-card/40 p-4">
      <div className="mb-3 flex items-center justify-between gap-2">
        <Label htmlFor="paste-headers" className="text-foreground text-sm font-medium">
          Paste raw headers or full source
        </Label>
        <span className="text-muted-foreground text-xs tabular-nums">
          {charCount.toLocaleString()} characters
        </span>
      </div>
      <Textarea
        id="paste-headers"
        value={text}
        onChange={(e) => setText(e.target.value)}
        placeholder={`Received: from mail-server.example.com (mail.example.com [203.0.113.1])\n\tby mx.recipient.com with ESMTPS id 1234abcd;\n\tTue, 5 May 2026 11:30:42 +0000\nReceived-SPF: pass (mx.recipient.com: domain of …) client-ip=203.0.113.1;\nFrom: "Acme Support" <support@acme.com>\nReply-To: support@acme.com\nSubject: Your invoice is ready\n…`}
        className="font-mono text-xs min-h-56 leading-relaxed"
        disabled={disabled}
        spellCheck={false}
      />
      <div className="mt-3 flex items-center justify-between gap-3">
        <p className="text-muted-foreground text-xs">
          Get this from <em>Show Original</em> (Gmail), <em>View Source</em>, or your
          mail program&apos;s &quot;Internet headers&quot; option. Your email is not
          uploaded.
        </p>
        <Button
          onClick={() => onSubmit(text)}
          disabled={!ready || disabled}
          size="sm"
          className="shrink-0"
        >
          <ScanLine data-icon="inline-start" />
          Scan
        </Button>
      </div>
    </div>
  )
}
