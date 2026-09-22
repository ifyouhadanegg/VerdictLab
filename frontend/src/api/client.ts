import type { FileLookupResponse } from '../types/verdict'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:8000'

export class ApiClientError extends Error {
  status: number

  constructor(message: string, status: number) {
    super(message)
    this.name = 'ApiClientError'
    this.status = status
  }
}

export async function lookupFileBySha256(
  sha256: string,
): Promise<FileLookupResponse> {
  const response = await fetch(`${API_BASE_URL}/api/v1/files/${sha256}`)

  if (!response.ok) {
    let message = `Request failed with status ${response.status}`

    try {
      const body = (await response.json()) as { detail?: string }
      if (body.detail) {
        message = body.detail
      }
    } catch {
      // Keep fallback message if response body is not JSON.
    }

    throw new ApiClientError(message, response.status)
  }

  return (await response.json()) as FileLookupResponse
}
