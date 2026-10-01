import { useMemo, useState } from 'react'
import { ApiClientError, lookupFileBySha256 } from './api/client'
import './App.css'
import type { FileLookupResponse } from './types/verdict'

const SHA256_PATTERN = /^[a-fA-F0-9]{64}$/

const examples = [
  {
    label: 'Clearly malicious',
    sha256:
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  },
  {
    label: 'Likely clean',
    sha256:
      'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
  },
  {
    label: 'Conflicting detections',
    sha256:
      'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
  },
  {
    label: 'Insufficient evidence',
    sha256:
      'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
  },
]

type ViewState = 'idle' | 'loading' | 'validationError' | 'apiError' | 'noResult' | 'result'

function bytesToHumanReadable(bytes: number | null): string {
  if (bytes === null) {
    return 'Not reported'
  }
  if (bytes < 1024) {
    return `${bytes} B`
  }
  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`
  }
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
}

function capitalize(value: string): string {
  return value.replace('_', ' ').replace(/\b\w/g, (char) => char.toUpperCase())
}

function App() {
  const [sha256Input, setSha256Input] = useState('')
  const [viewState, setViewState] = useState<ViewState>('idle')
  const [validationMessage, setValidationMessage] = useState('')
  const [apiMessage, setApiMessage] = useState('')
  const [result, setResult] = useState<FileLookupResponse | null>(null)

  const canSubmit = useMemo(
    () => sha256Input.trim().length > 0 && viewState !== 'loading',
    [sha256Input, viewState],
  )

  const runLookup = async (hashValue: string) => {
    const normalized = hashValue.trim().toLowerCase()
    if (!SHA256_PATTERN.test(normalized)) {
      setResult(null)
      setValidationMessage('Enter a valid SHA-256 hash with 64 hexadecimal characters.')
      setApiMessage('')
      setViewState('validationError')
      return
    }

    setValidationMessage('')
    setApiMessage('')
    setViewState('loading')

    try {
      const payload = await lookupFileBySha256(normalized)
      setResult(payload)
      setViewState('result')
    } catch (error) {
      setResult(null)
      if (error instanceof ApiClientError && error.status === 404) {
        setApiMessage(error.message)
        setViewState('noResult')
        return
      }

      setApiMessage(
        error instanceof Error
          ? error.message
          : 'Unexpected API error. Check backend status and try again.',
      )
      setViewState('apiError')
    }
  }

  const onSubmit: React.FormEventHandler<HTMLFormElement> = async (event) => {
    event.preventDefault()
    await runLookup(sha256Input)
  }

  const useExample = async (hashValue: string) => {
    setSha256Input(hashValue)
    await runLookup(hashValue)
  }

  const currentResult = result

  return (
    <div className="app-shell">
      <header className="app-header">
        <div>
          <p className="eyebrow">Security Verdict Explorer</p>
          <h1>VerdictLab</h1>
          <p className="subtitle">
            Explore synthetic examples or check a real SHA-256 hash against
            VirusTotal for an explainable, conservative verdict.
          </p>
        </div>
        <p className="synthetic-chip" aria-label="Synthetic Data">
          Synthetic + VirusTotal
        </p>
      </header>

      <main className="grid-layout">
        <section className="panel" aria-labelledby="lookup-title">
          <h2 id="lookup-title">Hash Lookup</h2>
          <form onSubmit={onSubmit} noValidate>
            <label htmlFor="sha256-input" className="field-label">
              SHA-256 hash
            </label>
            <input
              id="sha256-input"
              name="sha256"
              autoComplete="off"
              spellCheck={false}
              value={sha256Input}
              onChange={(event) => setSha256Input(event.target.value)}
              placeholder="Enter 64 hexadecimal characters"
              aria-describedby="sha-help"
              aria-invalid={viewState === 'validationError'}
            />
            <p id="sha-help" className="field-help">
              Hash only, no file upload. Real hashes are checked with VirusTotal.
            </p>

            <button type="submit" disabled={!canSubmit}>
              {viewState === 'loading' ? 'Analyzing...' : 'Analyze Hash'}
            </button>
          </form>

          <div className="example-wrap" aria-label="Synthetic examples">
            <p className="section-caption">Try a synthetic sample</p>
            <div className="example-grid">
              {examples.map((example) => (
                <button
                  key={example.sha256}
                  type="button"
                  className="example-button"
                  onClick={() => useExample(example.sha256)}
                >
                  <span>{example.label}</span>
                  <small>{example.sha256.slice(0, 12)}...</small>
                </button>
              ))}
            </div>
          </div>
        </section>

        <section className="panel" aria-live="polite" aria-labelledby="result-title">
          <h2 id="result-title">Verdict Output</h2>

          {viewState === 'idle' && (
            <p className="state-note">
              Submit a hash or click an example to view metadata, detections, and
              an explainable verdict.
            </p>
          )}

          {viewState === 'loading' && (
            <p className="state-note" role="status">
              Checking reputation sources...
            </p>
          )}

          {viewState === 'validationError' && (
            <p className="state-error" role="alert">
              {validationMessage}
            </p>
          )}

          {viewState === 'apiError' && (
            <p className="state-error" role="alert">
              API error: {apiMessage}
            </p>
          )}

          {viewState === 'noResult' && (
            <p className="state-note" role="status">
              {apiMessage || 'No report found for this hash.'}
            </p>
          )}

          {viewState === 'result' && currentResult && (
            <div className="result-stack">
              <p
                className="source-label"
                data-source={currentResult.synthetic_data ? 'synthetic' : 'virustotal'}
              >
                {currentResult.synthetic_data
                  ? currentResult.synthetic_notice
                  : 'Live reputation data from VirusTotal. No file was uploaded.'}
              </p>

              <article className="verdict-card">
                <p className="verdict-kicker">Verdict</p>
                <h3>{capitalize(currentResult.verdict.verdict)}</h3>
                <p>
                  Confidence: <strong>{capitalize(currentResult.verdict.confidence)}</strong>
                </p>
                <p>
                  Recommended action:{' '}
                  <strong>{currentResult.verdict.recommendation}</strong>
                </p>
              </article>

              <article className="subpanel" aria-label="Detection summary">
                <h4>Detection Counts</h4>
                <dl>
                  <div>
                    <dt>Malicious</dt>
                    <dd>{currentResult.detections.malicious}</dd>
                  </div>
                  <div>
                    <dt>Suspicious</dt>
                    <dd>{currentResult.detections.suspicious}</dd>
                  </div>
                  <div>
                    <dt>Undetected</dt>
                    <dd>{currentResult.detections.undetected}</dd>
                  </div>
                  <div>
                    <dt>Harmless</dt>
                    <dd>{currentResult.detections.harmless}</dd>
                  </div>
                </dl>
              </article>

              <article className="subpanel" aria-label="File metadata">
                <h4>File Metadata</h4>
                <dl>
                  <div>
                    <dt>File name</dt>
                    <dd>{currentResult.metadata.file_name || 'Not reported'}</dd>
                  </div>
                  <div>
                    <dt>File type</dt>
                    <dd>{currentResult.metadata.file_type || 'Not reported'}</dd>
                  </div>
                  <div>
                    <dt>Size</dt>
                    <dd>{bytesToHumanReadable(currentResult.metadata.file_size_bytes)}</dd>
                  </div>
                  <div>
                    <dt>Signed</dt>
                    <dd>
                      {currentResult.metadata.signed === null
                        ? 'Not reported'
                        : currentResult.metadata.signed
                          ? 'Yes'
                          : 'No'}
                    </dd>
                  </div>
                  <div>
                    <dt>First seen</dt>
                    <dd>
                      {currentResult.metadata.first_seen_days_ago === null
                        ? 'Not reported'
                        : `${currentResult.metadata.first_seen_days_ago} days ago`}
                    </dd>
                  </div>
                  <div>
                    <dt>Prevalence score</dt>
                    <dd>
                      {currentResult.metadata.prevalence_score === null
                        ? 'Not reported'
                        : `${currentResult.metadata.prevalence_score}/100`}
                    </dd>
                  </div>
                </dl>
              </article>

              <article className="subpanel" aria-label="Rationale">
                <h4>Rationale</h4>
                <p>{currentResult.verdict.explanation}</p>
                <ul>
                  {currentResult.verdict.rules_triggered.map((rule) => (
                    <li key={rule}>{rule}</li>
                  ))}
                </ul>
                <p className="safety-note">{currentResult.verdict.safety_note}</p>
              </article>
            </div>
          )}
        </section>
      </main>
    </div>
  )
}

export default App
