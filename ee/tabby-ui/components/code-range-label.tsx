'use client'

import { LineRange } from '@/lib/integrations/ide'

import { cn } from '@/lib/utils'

export function CodeRangeLabel({
  range,
  className,
  prefix = ':'
}: {
  range: LineRange | undefined
  className?: string
  prefix?: string
}) {
  if (!range) return null

  const isMultiLine = range.end - range.start > 1

  return (
    <span className={cn('text-muted-foreground', className)}>
      {isMultiLine
        ? `${prefix}${range.start}-${range.end}`
        : `${prefix}${range.start}`}
    </span>
  )
}
