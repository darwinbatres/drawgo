/**
 * WebSocket Client — Real-time board collaboration
 *
 * Connects to the Go backend's WebSocket endpoint for:
 * - Live cursor positions
 * - Presence (who's viewing)
 * - Scene updates (future: collaborative editing)
 *
 * Auth: JWT token or share token passed as query param.
 */

import type {
  WSMessage,
  CursorPayload,
  PresencePayload,
} from "@/types";

export type WSEventType =
  | "connected"
  | "disconnected"
  | "cursor_update"
  | "presence"
  | "joined"
  | "left"
  | "scene_update"
  | "welcome"
  | "error";

export type WSEventHandler = (type: WSEventType, payload: unknown) => void;

interface WSClientOptions {
  boardId: string;
  /** JWT access token (for authenticated users) */
  token?: string;
  /** Share link token (for anonymous viewers) */
  shareToken?: string;
  onEvent: WSEventHandler;
}

const WS_RECONNECT_DELAYS = [1000, 2000, 4000, 8000, 16000];
const WS_PING_INTERVAL = 30_000;

export class WSClient {
  private ws: WebSocket | null = null;
  private options: WSClientOptions;
  private reconnectAttempt = 0;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private pingTimer: ReturnType<typeof setInterval> | null = null;
  private disposed = false;

  constructor(options: WSClientOptions) {
    this.options = options;
  }

  connect(): void {
    if (this.disposed) return;
    this.cleanup();

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    // In Docker, Caddy proxies /api/v1/* → backend (including WebSocket upgrades).
    // In local dev, Next.js rewrites cannot proxy WebSocket connections, so we
    // connect directly to the Go backend via NEXT_PUBLIC_API_URL if available.
    const apiUrl = process.env.NEXT_PUBLIC_API_URL;
    let wsBase: string;
    if (apiUrl) {
      // Local dev: connect directly to backend (e.g., ws://localhost:8090)
      const parsed = new URL(apiUrl);
      const wsProto = parsed.protocol === "https:" ? "wss:" : "ws:";
      wsBase = `${wsProto}//${parsed.host}`;
    } else {
      // Docker/production: same host, Caddy handles WS proxy
      wsBase = `${protocol}//${window.location.host}`;
    }
    const params = new URLSearchParams();

    // In browser contexts, the JWT is sent automatically via httpOnly cookies
    // (Caddy/backend handle the WS upgrade with cookies). Only send the token
    // as a query param for non-browser clients or when using share tokens,
    // since query params leak to server logs and browser history.
    if (this.options.shareToken) {
      params.set("share", this.options.shareToken);
    }
    // Note: authenticated users rely on httpOnly cookie (auto-sent by browser)

    const url = `${wsBase}/api/v1/ws/boards/${this.options.boardId}?${params.toString()}`;

    try {
      this.ws = new WebSocket(url);
    } catch {
      this.scheduleReconnect();
      return;
    }

    this.ws.onopen = () => {
      this.reconnectAttempt = 0;
      this.startPing();
      this.options.onEvent("connected", null);
    };

    this.ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data) as WSMessage;
        this.handleMessage(msg);
      } catch {
        // Ignore malformed messages
      }
    };

    this.ws.onclose = (event) => {
      this.stopPing();
      this.options.onEvent("disconnected", { code: event.code });
      if (!this.disposed && event.code !== 1000) {
        this.scheduleReconnect();
      }
    };

    this.ws.onerror = () => {
      // onclose will fire after onerror
    };
  }

  private handleMessage(msg: WSMessage): void {
    switch (msg.type) {
      case "cursor_update":
        this.options.onEvent("cursor_update", msg.payload as CursorPayload);
        break;
      case "presence":
        this.options.onEvent("presence", msg.payload as PresencePayload);
        break;
      case "scene_synced":
      case "broadcast":
        this.options.onEvent("scene_update", msg.payload);
        break;
      case "error":
        this.options.onEvent("error", msg.payload);
        break;
      case "pong":
        break;
      case "welcome":
        this.options.onEvent("welcome", msg.payload);
        break;
      case "joined":
        this.options.onEvent("joined", msg.payload);
        break;
      case "left":
        this.options.onEvent("left", msg.payload);
        break;
    }
  }

  sendCursorMove(x: number, y: number): void {
    this.send({
      type: "cursor_move",
      payload: { x, y },
    });
  }

  sendSceneUpdate(data: { elements: unknown; files?: unknown }): void {
    this.send({
      type: "scene_update",
      payload: data,
    });
  }

  private send(msg: Omit<WSMessage, "senderId">): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(msg));
    }
  }

  private startPing(): void {
    this.stopPing();
    this.pingTimer = setInterval(() => {
      this.send({ type: "ping", payload: null });
    }, WS_PING_INTERVAL);
  }

  private stopPing(): void {
    if (this.pingTimer) {
      clearInterval(this.pingTimer);
      this.pingTimer = null;
    }
  }

  private scheduleReconnect(): void {
    if (this.disposed) return;

    const delay =
      WS_RECONNECT_DELAYS[
        Math.min(this.reconnectAttempt, WS_RECONNECT_DELAYS.length - 1)
      ];
    this.reconnectAttempt++;

    this.reconnectTimer = setTimeout(() => {
      this.connect();
    }, delay);
  }

  private cleanup(): void {
    this.stopPing();
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.ws) {
      this.ws.onopen = null;
      this.ws.onmessage = null;
      this.ws.onclose = null;
      this.ws.onerror = null;
      if (
        this.ws.readyState === WebSocket.OPEN ||
        this.ws.readyState === WebSocket.CONNECTING
      ) {
        this.ws.close(1000);
      }
      this.ws = null;
    }
  }

  disconnect(): void {
    this.disposed = true;
    this.cleanup();
  }

  get isConnected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }
}
