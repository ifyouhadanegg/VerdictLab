export interface FileMetadata {
  sha256: string
  file_name: string
  file_type: string
  file_size_bytes: number | null
  first_seen_days_ago: number | null
  prevalence_score: number | null
  signed: boolean | null
}

export interface DetectionCounts {
  malicious: number
  suspicious: number
  undetected: number
  harmless: number
}

export type Recommendation =
  | 'Allow'
  | 'Block'
  | 'Rescan'
  | 'Detonate'
  | 'Human Review'

export type VerdictLabel =
  | 'malicious'
  | 'suspicious'
  | 'mixed'
  | 'likely_clean'
  | 'unknown'

export interface VerdictResult {
  verdict: VerdictLabel
  recommendation: Recommendation
  confidence: string
  risk_score: number
  rules_triggered: string[]
  explanation: string
  safety_note: string
}

export interface FileLookupResponse {
  synthetic_data: boolean
  synthetic_notice: string | null
  metadata: FileMetadata
  detections: DetectionCounts
  verdict: VerdictResult
}
