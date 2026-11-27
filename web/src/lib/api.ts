// Same-origin requests only.  The server refuses cross-origin and non-JSON
// writes, so every POST sends application/json.

export const DEMO =
  typeof window !== "undefined" &&
  new URLSearchParams(window.location.search).has("demo")

export async function getJSON<T>(path: string): Promise<T | null> {
  try {
    const response = await fetch(path, { cache: "no-store" })
    if (!response.ok) return null
    return (await response.json()) as T
  } catch {
    return null
  }
}

export interface PostResult<T> {
  ok: boolean
  status: number
  data: T | null
  error?: string
}

export async function postJSON<T>(
  path: string,
  body: unknown
): Promise<PostResult<T>> {
  try {
    const response = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body ?? {}),
    })
    let data: T | null = null
    try {
      data = (await response.json()) as T
    } catch {
      data = null
    }
    return { ok: response.ok, status: response.status, data }
  } catch (error) {
    return {
      ok: false,
      status: 0,
      data: null,
      error: error instanceof Error ? error.message : String(error),
    }
  }
}

/** Downloads served by the API.  Kept in one place so the demo can disable them. */
export const DOWNLOADS = {
  csv: "/api/run/export.csv",
  jsonl: "/api/run/export.jsonl",
  json: "/api/run/export.json",
  history: "/api/history/export.json",
  capacity: "/api/capacity/export.json",
  report: "/report",
} as const
