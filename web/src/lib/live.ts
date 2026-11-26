import { useSyncExternalStore } from "react"

import { DEMO, getJSON } from "@/lib/api"
import { createDemo } from "@/lib/demo"
import type { Snapshot } from "@/lib/schema"

export type Connection =
  "connecting" | "live" | "polling" | "reconnecting" | "demo"

export interface LiveState {
  snapshot: Snapshot | null
  connection: Connection
  /** Epoch ms of the last snapshot, for the "updated" hint. */
  receivedAt: number
}

type Listener = () => void

/**
 * The live run snapshot, pushed by the server over Server-Sent Events once a
 * second.  EventSource reconnects by itself; after three consecutive errors the
 * store falls back to polling /api/stats rather than spinning forever, which is
 * what the original dashboard did and what proxies that break SSE need.
 */
class LiveStore {
  private state: LiveState = {
    snapshot: null,
    connection: "connecting",
    receivedAt: 0,
  }
  private listeners = new Set<Listener>()
  private pollTimer: number | null = null
  private errors = 0
  private started = false

  subscribe = (listener: Listener) => {
    this.listeners.add(listener)
    this.start()
    return () => {
      this.listeners.delete(listener)
    }
  }

  getState = () => this.state

  /** Re-read the snapshot now, e.g. straight after Start or Stop. */
  refresh = async () => {
    if (DEMO) return
    const snapshot = await getJSON<Snapshot>("/api/stats")
    if (snapshot) this.publish(snapshot, this.state.connection)
  }

  private set(next: Partial<LiveState>) {
    this.state = { ...this.state, ...next }
    for (const listener of this.listeners) listener()
  }

  private publish(snapshot: Snapshot, connection: Connection) {
    this.set({ snapshot, connection, receivedAt: Date.now() })
  }

  private start() {
    if (this.started || typeof window === "undefined") return
    this.started = true
    if (DEMO) {
      const demo = createDemo()
      this.publish(demo.snapshot(), "demo")
      window.setInterval(() => this.publish(demo.snapshot(), "demo"), 1000)
      return
    }
    this.openStream()
  }

  private openStream() {
    if (typeof window.EventSource !== "function") {
      this.startPolling()
      return
    }
    this.set({ connection: "connecting" })
    let source: EventSource
    try {
      source = new EventSource("/api/stream")
    } catch {
      this.startPolling()
      return
    }
    source.onopen = () => {
      this.errors = 0
      this.set({ connection: "live" })
    }
    source.addEventListener("stats", (event) => {
      this.errors = 0
      try {
        this.publish(JSON.parse((event as MessageEvent<string>).data), "live")
      } catch {
        // A truncated frame; the next one arrives within a second.
      }
    })
    source.onerror = () => {
      this.errors += 1
      if (this.pollTimer !== null) return
      if (this.errors >= 3) {
        source.close()
        this.startPolling()
      } else {
        this.set({ connection: "reconnecting" })
      }
    }
  }

  private startPolling() {
    if (this.pollTimer !== null) return
    this.set({ connection: "polling" })
    const tick = async () => {
      const snapshot = await getJSON<Snapshot>("/api/stats")
      if (snapshot) this.publish(snapshot, "polling")
    }
    void tick()
    this.pollTimer = window.setInterval(tick, 1000)
  }
}

export const live = new LiveStore()

export function useLive(): LiveState {
  return useSyncExternalStore(live.subscribe, live.getState, live.getState)
}
