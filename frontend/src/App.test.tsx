import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import App from './App'

const validSha = 'a'.repeat(64)

function fillAndSubmit(value: string) {
  fireEvent.change(screen.getByLabelText(/sha-256 hash/i), {
    target: { value },
  })
  fireEvent.click(screen.getByRole('button', { name: /analyze hash/i }))
}

describe('VerdictLab frontend', () => {
  it('shows validation message for invalid hashes', async () => {
    render(<App />)

    fillAndSubmit('not-a-hash')

    expect(
      await screen.findByText(/enter a valid sha-256 hash/i),
    ).toBeInTheDocument()
  })

  it('renders lookup result on successful API response', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        synthetic_data: true,
        synthetic_notice: 'Synthetic fixture',
        metadata: {
          sha256: validSha,
          file_name: 'sample.bin',
          file_type: 'binary',
          file_size_bytes: 1024,
          first_seen_days_ago: 12,
          prevalence_score: 50,
          signed: true,
        },
        detections: { malicious: 1, suspicious: 2, undetected: 20, harmless: 0 },
        verdict: {
          verdict: 'suspicious',
          recommendation: 'Detonate',
          confidence: 'medium',
          risk_score: 66,
          rules_triggered: ['Some suspicious detections present.'],
          explanation: 'Risk is elevated.',
          safety_note: 'Zero detections do not prove a file is safe.',
        },
      }),
    })

    vi.stubGlobal('fetch', fetchMock)
    render(<App />)

    fillAndSubmit(validSha)

    expect(await screen.findByText(/detonate/i)).toBeInTheDocument()
    expect(screen.getByText(/risk is elevated/i)).toBeInTheDocument()

    vi.unstubAllGlobals()
  })

  it('shows no-result state when API returns 404', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: false,
      status: 404,
      json: async () => ({ detail: 'VirusTotal has no report for this hash' }),
    })

    vi.stubGlobal('fetch', fetchMock)
    render(<App />)

    fillAndSubmit(validSha)

    await waitFor(() => {
      expect(screen.getByText(/no report for this hash/i)).toBeInTheDocument()
    })

    vi.unstubAllGlobals()
  })
})
