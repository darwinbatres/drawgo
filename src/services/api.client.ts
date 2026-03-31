// =============================================================================
// API Client — Go backend (cookie-based JWT auth, /api/v1 prefix)
// =============================================================================
// All requests go through the Next.js proxy rewrite to the Go backend.
// Auth cookies are sent automatically (httpOnly, same-origin).
// =============================================================================

import type {
  Board,
  BoardVersion,
  User,
  Organization,
  Membership,
  ShareLink,
  SharedBoardData,
  StorageInfo,
  SystemStatsResult,
  OrgStatsResult,
  HubStats,
  AuthResponse,
  UploadedFile,
  FileAsset,
  AuditEvent,
  BackendLogEntry,
  LogLevelSummary,
} from "@/types";

// -----------------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------------

/** Go backend response envelope */
interface Envelope<T> {
  data: T;
  error: null;
  meta?: { total: number; limit: number; offset: number };
}

/** Go backend error envelope */
interface ErrorEnvelope {
  data: null;
  error: { code: string; message: string; details?: unknown };
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface BoardSearchParams {
  orgId: string;
  query?: string;
  tags?: string[];
  archived?: boolean;
  limit?: number;
  offset?: number;
}

export interface CreateBoardParams {
  title: string;
  description?: string;
  tags?: string[];
  sceneJson?: unknown;
}

export interface UpdateBoardParams {
  title?: string;
  description?: string;
  tags?: string[];
  isArchived?: boolean;
}

export interface SaveVersionParams {
  sceneJson: unknown;
  appStateJson?: unknown;
  label?: string;
  expectedEtag?: string;
  thumbnail?: string;
}

export interface SaveVersionResult {
  version: BoardVersion;
  etag: string;
  conflict?: boolean;
  currentEtag?: string;
}

/** Board with its latest version data (from GET /boards/:id) */
export interface BoardWithScene extends Board {
  latestVersion?: {
    id: string;
    version: number;
    sceneJson: unknown;
    appStateJson?: unknown;
    createdAt: string;
    createdById: string;
    label?: string;
  };
}

// -----------------------------------------------------------------------------
// API Error class
// -----------------------------------------------------------------------------

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public code?: string,
    public details?: unknown
  ) {
    super(message);
    this.name = "ApiError";
  }
}

// -----------------------------------------------------------------------------
// Fetch helper with envelope unwrapping
// -----------------------------------------------------------------------------

const API_PREFIX = "/api/v1";

async function fetchApi<T>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const url = `${API_PREFIX}${path}`;

  const response = await fetch(url, {
    ...options,
    credentials: "include", // send cookies
    headers: {
      "Content-Type": "application/json",
      ...options.headers,
    },
  });

  // 204 No Content
  if (response.status === 204) {
    return undefined as T;
  }

  const body = await response.json().catch(() => null);

  if (!response.ok) {
    const err = (body as ErrorEnvelope)?.error;
    throw new ApiError(
      response.status,
      err?.message || `Request failed: ${response.status}`,
      err?.code,
      err?.details
    );
  }

  // Unwrap envelope — Go backend wraps everything in { data, error, meta }
  if (body && typeof body === "object" && "data" in body) {
    return (body as Envelope<T>).data;
  }

  return body as T;
}

/** Same as fetchApi but returns {data, meta} for paginated endpoints */
async function fetchPaginated<T>(
  path: string,
  options: RequestInit = {}
): Promise<PaginatedResponse<T>> {
  const url = `${API_PREFIX}${path}`;

  const response = await fetch(url, {
    ...options,
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...options.headers,
    },
  });

  const body = await response.json().catch(() => null);

  if (!response.ok) {
    const err = (body as ErrorEnvelope)?.error;
    throw new ApiError(
      response.status,
      err?.message || `Request failed: ${response.status}`,
      err?.code,
      err?.details
    );
  }

  const envelope = body as Envelope<T[]>;
  return {
    items: envelope.data || [],
    total: envelope.meta?.total ?? 0,
    limit: envelope.meta?.limit ?? 50,
    offset: envelope.meta?.offset ?? 0,
  };
}

// -----------------------------------------------------------------------------
// Auth API
// -----------------------------------------------------------------------------

export const authApi = {
  async login(
    email: string,
    password: string
  ): Promise<AuthResponse> {
    return fetchApi<AuthResponse>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });
  },

  async register(
    email: string,
    password: string,
    name: string
  ): Promise<AuthResponse> {
    return fetchApi<AuthResponse>("/auth/register", {
      method: "POST",
      body: JSON.stringify({ email, password, name }),
    });
  },

  async refresh(): Promise<AuthResponse> {
    return fetchApi<AuthResponse>("/auth/refresh", {
      method: "POST",
    });
  },

  async logout(): Promise<void> {
    await fetchApi<void>("/auth/logout", { method: "POST" });
  },

  async me(): Promise<User> {
    return fetchApi<User>("/auth/me");
  },
};

// -----------------------------------------------------------------------------
// Organization API
// -----------------------------------------------------------------------------

export const orgApi = {
  async list(): Promise<PaginatedResponse<Organization>> {
    return fetchPaginated<Organization>("/orgs");
  },

  async create(name: string, slug: string): Promise<Organization> {
    return fetchApi<Organization>("/orgs", {
      method: "POST",
      body: JSON.stringify({ name, slug }),
    });
  },

  async update(orgId: string, params: { name?: string }): Promise<Organization> {
    return fetchApi<Organization>(`/orgs/${orgId}`, {
      method: "PATCH",
      body: JSON.stringify(params),
    });
  },

  async delete(orgId: string): Promise<void> {
    await fetchApi<void>(`/orgs/${orgId}`, { method: "DELETE" });
  },

  async getStorage(orgId: string): Promise<StorageInfo> {
    return fetchApi<StorageInfo>(`/orgs/${orgId}/storage`);
  },

  async stats(orgId: string): Promise<OrgStatsResult> {
    return fetchApi<OrgStatsResult>(`/orgs/${orgId}/stats`);
  },
};

// -----------------------------------------------------------------------------
// Member API
// -----------------------------------------------------------------------------

export const memberApi = {
  async list(orgId: string): Promise<PaginatedResponse<Membership>> {
    return fetchPaginated<Membership>(`/orgs/${orgId}/members`);
  },

  async invite(
    orgId: string,
    email: string,
    role: string
  ): Promise<Membership> {
    return fetchApi<Membership>(`/orgs/${orgId}/members`, {
      method: "POST",
      body: JSON.stringify({ email, role }),
    });
  },

  async updateRole(
    orgId: string,
    membershipId: string,
    role: string
  ): Promise<Membership> {
    return fetchApi<Membership>(`/orgs/${orgId}/members/${membershipId}`, {
      method: "PATCH",
      body: JSON.stringify({ role }),
    });
  },

  async remove(orgId: string, membershipId: string): Promise<void> {
    await fetchApi<void>(`/orgs/${orgId}/members/${membershipId}`, {
      method: "DELETE",
    });
  },
};

// -----------------------------------------------------------------------------
// Board API
// -----------------------------------------------------------------------------

export const boardApi = {
  async list(params: BoardSearchParams): Promise<PaginatedResponse<Board>> {
    const searchParams = new URLSearchParams();
    if (params.query) searchParams.set("q", params.query);
    if (params.tags?.length) searchParams.set("tags", params.tags.join(","));
    if (params.archived !== undefined)
      searchParams.set("archived", String(params.archived));
    if (params.limit !== undefined)
      searchParams.set("limit", String(params.limit));
    if (params.offset !== undefined)
      searchParams.set("offset", String(params.offset));

    const qs = searchParams.toString();
    return fetchPaginated<Board>(
      `/orgs/${params.orgId}/boards${qs ? `?${qs}` : ""}`
    );
  },

  async get(boardId: string): Promise<BoardWithScene> {
    return fetchApi<BoardWithScene>(`/boards/${boardId}`);
  },

  async create(orgId: string, params: CreateBoardParams): Promise<Board> {
    return fetchApi<Board>(`/orgs/${orgId}/boards`, {
      method: "POST",
      body: JSON.stringify(params),
    });
  },

  async update(boardId: string, params: UpdateBoardParams): Promise<Board> {
    return fetchApi<Board>(`/boards/${boardId}`, {
      method: "PATCH",
      body: JSON.stringify(params),
    });
  },

  async archive(boardId: string, archive: boolean = true): Promise<Board> {
    return fetchApi<Board>(`/boards/${boardId}`, {
      method: "PATCH",
      body: JSON.stringify({ isArchived: archive }),
    });
  },

  async delete(boardId: string): Promise<void> {
    await fetchApi<void>(`/boards/${boardId}`, { method: "DELETE" });
  },

  async saveVersion(
    boardId: string,
    params: SaveVersionParams
  ): Promise<SaveVersionResult> {
    return fetchApi<SaveVersionResult>(`/boards/${boardId}/versions`, {
      method: "POST",
      body: JSON.stringify(params),
    });
  },

  async getVersions(
    boardId: string,
    options?: { limit?: number; offset?: number }
  ): Promise<PaginatedResponse<BoardVersion>> {
    const params = new URLSearchParams();
    if (options?.limit !== undefined)
      params.set("limit", String(options.limit));
    if (options?.offset !== undefined)
      params.set("offset", String(options.offset));

    const qs = params.toString();
    return fetchPaginated<BoardVersion>(
      `/boards/${boardId}/versions${qs ? `?${qs}` : ""}`
    );
  },

  async getVersion(boardId: string, version: number): Promise<BoardVersion> {
    return fetchApi<BoardVersion>(`/boards/${boardId}/versions/${version}`);
  },

  async restoreVersion(
    boardId: string,
    version: number
  ): Promise<{ version: BoardVersion; etag: string }> {
    return fetchApi<{ version: BoardVersion; etag: string }>(
      `/boards/${boardId}/versions/${version}/restore`,
      { method: "POST" }
    );
  },

  async getStorage(boardId: string): Promise<StorageInfo> {
    return fetchApi<StorageInfo>(`/boards/${boardId}/storage`);
  },
};

// -----------------------------------------------------------------------------
// Share API
// -----------------------------------------------------------------------------

export const shareApi = {
  async create(
    boardId: string,
    role: string,
    expiresAt?: string
  ): Promise<ShareLink> {
    return fetchApi<ShareLink>(`/boards/${boardId}/share`, {
      method: "POST",
      body: JSON.stringify({ role, expiresAt }),
    });
  },

  async list(boardId: string): Promise<PaginatedResponse<ShareLink>> {
    return fetchPaginated<ShareLink>(`/boards/${boardId}/share`);
  },

  async revoke(boardId: string, linkId: string): Promise<void> {
    await fetchApi<void>(`/boards/${boardId}/share/${linkId}`, {
      method: "DELETE",
    });
  },

  async getShared(token: string): Promise<SharedBoardData> {
    return fetchApi<SharedBoardData>(`/share/${token}`);
  },
};

// -----------------------------------------------------------------------------
// File API
// -----------------------------------------------------------------------------

export const fileApi = {
  async upload(boardId: string, file: File): Promise<UploadedFile> {
    const formData = new FormData();
    formData.append("file", file);

    const url = `${API_PREFIX}/boards/${boardId}/files`;
    const response = await fetch(url, {
      method: "POST",
      credentials: "include",
      body: formData,
      // Don't set Content-Type — browser sets multipart boundary
    });

    const body = await response.json().catch(() => null);
    if (!response.ok) {
      const err = (body as ErrorEnvelope)?.error;
      throw new ApiError(
        response.status,
        err?.message || "Upload failed",
        err?.code
      );
    }

    if (body && typeof body === "object" && "data" in body) {
      return (body as Envelope<UploadedFile>).data;
    }
    return body as UploadedFile;
  },

  async list(boardId: string): Promise<PaginatedResponse<FileAsset>> {
    return fetchPaginated<FileAsset>(`/boards/${boardId}/files`);
  },

  async getUrl(boardId: string, fileId: string): Promise<string> {
    return `${API_PREFIX}/boards/${boardId}/files/${fileId}`;
  },
};

// -----------------------------------------------------------------------------
// Audit API
// -----------------------------------------------------------------------------

export const auditApi = {
  async list(
    orgId: string,
    options?: { limit?: number; offset?: number; action?: string }
  ): Promise<PaginatedResponse<AuditEvent>> {
    const params = new URLSearchParams();
    if (options?.limit !== undefined)
      params.set("limit", String(options.limit));
    if (options?.offset !== undefined)
      params.set("offset", String(options.offset));
    if (options?.action) params.set("action", options.action);

    const qs = params.toString();
    return fetchPaginated<AuditEvent>(
      `/orgs/${orgId}/audit${qs ? `?${qs}` : ""}`
    );
  },

  async stats(
    orgId: string
  ): Promise<{
    totalEvents: number;
    byAction: { action: string; count: number }[];
  }> {
    return fetchApi(`/orgs/${orgId}/audit/stats`);
  },

  async systemStats(): Promise<SystemStatsResult> {
    return fetchApi("/stats");
  },
};

// =============================================================================
// WebSocket Stats API
// =============================================================================

export const wsApi = {
  async stats(): Promise<HubStats> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);
    try {
      return await fetchApi<HubStats>("/ws/stats", { signal: controller.signal });
    } finally {
      clearTimeout(timer);
    }
  },
};

// =============================================================================
// Backend Logs API
// =============================================================================

export const logsApi = {
  async query(options?: {
    level?: string;
    search?: string;
    start?: string;
    end?: string;
    limit?: number;
    offset?: number;
  }): Promise<PaginatedResponse<BackendLogEntry>> {
    const params = new URLSearchParams();
    if (options?.level) params.set("level", options.level);
    if (options?.search) params.set("search", options.search);
    if (options?.start) params.set("start", options.start);
    if (options?.end) params.set("end", options.end);
    if (options?.limit !== undefined) params.set("limit", String(options.limit));
    if (options?.offset !== undefined) params.set("offset", String(options.offset));

    const qs = params.toString();
    return fetchPaginated<BackendLogEntry>(`/logs${qs ? `?${qs}` : ""}`);
  },

  async summary(): Promise<LogLevelSummary> {
    return fetchApi<LogLevelSummary>("/logs/summary");
  },
};

// -----------------------------------------------------------------------------
// Default export
// -----------------------------------------------------------------------------

const apiClient = {
  auth: authApi,
  org: orgApi,
  member: memberApi,
  board: boardApi,
  share: shareApi,
  file: fileApi,
  audit: auditApi,
  ws: wsApi,
  logs: logsApi,
};

export default apiClient;
