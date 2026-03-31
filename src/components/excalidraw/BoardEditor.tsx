/**
 * BoardEditor - Main Excalidraw editor component with autosave
 *
 * Features:
 * - Smart autosave (only saves when content actually changes)
 * - Save status indicator
 * - Version history sidebar
 * - Conflict detection via ETags
 * - Markdown card insertion with mermaid.js support
 *
 * All data is persisted to the database via API
 */

// Excalidraw styles - imported here to avoid loading on non-editor pages
import "@excalidraw/excalidraw/index.css";

import React, { useEffect, useRef, useState, useCallback } from "react";
import dynamic from "next/dynamic";
import { toast } from "sonner";
import type { BoardVersion, SaveStatus, CursorPayload, PresencePayload, ViewerInfo, WelcomePayload } from "@/types";
import { boardApi, ApiError, type BoardWithScene } from "@/services/api.client";
import { WSClient, type WSEventType } from "@/services/ws.client";
import { stripVolatileAppState } from "@/lib/utils";
import { useApp } from "@/contexts/AppContext";
import { SaveIndicator } from "./SaveIndicator";
import { VersionHistory } from "./VersionHistory";
import MarkdownCard from "./MarkdownCard";
import MarkdownCardEditor from "./MarkdownCardEditor";
import RichTextCard from "./RichTextCard";
import RichTextCardEditor from "./RichTextCardEditor";
import { Modal } from "@/components/ui/Modal";
import { Button } from "@/components/ui/Button";

// Dynamic import for Excalidraw (it needs to be client-side only)
const Excalidraw = dynamic(
  async () => (await import("@excalidraw/excalidraw")).Excalidraw,
  { ssr: false }
);

// Dynamic import for Footer component
const Footer = dynamic(
  async () => (await import("@excalidraw/excalidraw")).Footer,
  { ssr: false }
);

// We'll import exportToBlob dynamically when needed
let exportToBlob:
  | typeof import("@excalidraw/excalidraw")["exportToBlob"]
  | null = null;

interface BoardEditorProps {
  boardId: string;
  onTitleChange?: (title: string) => void;
  /** When true, the editor is read-only (view mode) */
  viewMode?: boolean;
  /** Callback to toggle view mode */
  onViewModeChange?: (viewMode: boolean) => void;
  /** Pre-loaded board data (used by shared pages to skip auth-protected fetch) */
  preloadedBoard?: BoardWithScene;
  /** Share link token for anonymous WebSocket access */
  shareToken?: string;
}

// Autosave interval from environment variable (default: 10 seconds)
const AUTOSAVE_INTERVAL = parseInt(
  process.env.NEXT_PUBLIC_AUTOSAVE_INTERVAL_MS || "10000",
  10
);

// Debounce interval for intermediate WS broadcasts (real-time sync without save)
const WS_BROADCAST_INTERVAL = parseInt(
  process.env.NEXT_PUBLIC_WS_BROADCAST_INTERVAL_MS || "1000",
  10
);

// Use any for Excalidraw types since their internal types aren't fully exported
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type ExcalidrawElements = readonly any[];
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type ExcalidrawAppState = any;
// BinaryFiles type: { [fileId: string]: { mimeType: string; id: string; dataURL: string; created: number; } }
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type BinaryFiles = Record<string, any>;

// Excalidraw API type
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type BinaryFileData = any;

interface ExcalidrawAPI {
  getSceneElements: () => ExcalidrawElements;
  getAppState: () => ExcalidrawAppState;
  getFiles: () => BinaryFiles;
  updateScene: (data: {
    elements?: ExcalidrawElements;
    appState?: ExcalidrawAppState;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    collaborators?: Map<string, any>;
  }) => void;
  addFiles: (files: BinaryFileData[]) => void;
}

/**
 * Strip markdown formatting to get plain text for search indexing.
 * Removes common markdown syntax while preserving readable text.
 */
function stripMarkdownToPlainText(markdown: string): string {
  return (
    markdown
      // Remove code blocks (```...```)
      .replace(/```[\s\S]*?```/g, "")
      // Remove inline code (`...`)
      .replace(/`[^`]+`/g, "")
      // Remove headers (# ## ### etc) but keep the text
      .replace(/^#{1,6}\s+/gm, "")
      // Remove bold/italic markers
      .replace(/\*\*([^*]+)\*\*/g, "$1")
      .replace(/\*([^*]+)\*/g, "$1")
      .replace(/__([^_]+)__/g, "$1")
      .replace(/_([^_]+)_/g, "$1")
      // Remove links but keep text [text](url) -> text
      .replace(/\[([^\]]+)\]\([^)]+\)/g, "$1")
      // Remove images ![alt](url)
      .replace(/!\[([^\]]*)\]\([^)]+\)/g, "$1")
      // Remove horizontal rules
      .replace(/^[-*_]{3,}\s*$/gm, "")
      // Remove list markers
      .replace(/^[\s]*[-*+]\s+/gm, "")
      .replace(/^[\s]*\d+\.\s+/gm, "")
      // Remove blockquotes
      .replace(/^>\s+/gm, "")
      // Clean up extra whitespace
      .replace(/\n{3,}/g, "\n\n")
      .trim()
  );
}

/**
 * Generate a simple hash of scene content to detect actual changes.
 * Only includes properties that matter for persistence (not UI state).
 */
function hashSceneContent(
  elements: ExcalidrawElements,
  files: BinaryFiles
): string {
  // Only hash non-deleted elements and their important properties
  const elementData = elements
    .filter((el) => !el.isDeleted)
    .map((el) => ({
      id: el.id,
      type: el.type,
      x: el.x,
      y: el.y,
      width: el.width,
      height: el.height,
      angle: el.angle,
      strokeColor: el.strokeColor,
      backgroundColor: el.backgroundColor,
      fillStyle: el.fillStyle,
      strokeWidth: el.strokeWidth,
      roughness: el.roughness,
      opacity: el.opacity,
      text: el.text,
      points: el.points,
      fileId: el.fileId,
      link: el.link,
      customData: el.customData,
    }));

  const fileIds = Object.keys(files).sort();

  // Simple string hash for comparison
  const content = JSON.stringify({ elements: elementData, fileIds });
  let hash = 0;
  for (let i = 0; i < content.length; i++) {
    const char = content.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash = hash & hash; // Convert to 32bit integer
  }
  return hash.toString(36);
}

/**
 * Generate a thumbnail image from the current scene.
 * Returns a base64 data URL or null if generation fails.
 */
async function generateThumbnail(
  elements: ExcalidrawElements,
  appState: ExcalidrawAppState,
  files: BinaryFiles
): Promise<string | null> {
  try {
    // Lazy load exportToBlob
    if (!exportToBlob) {
      const excalidrawModule = await import("@excalidraw/excalidraw");
      exportToBlob = excalidrawModule.exportToBlob;
    }

    // Filter out deleted elements
    const visibleElements = elements.filter((el) => !el.isDeleted);

    if (visibleElements.length === 0) {
      return null; // No content to thumbnail
    }

    // Generate thumbnail blob
    const blob = await exportToBlob({
      elements: visibleElements,
      appState: {
        ...appState,
        exportBackground: true,
        viewBackgroundColor: appState.viewBackgroundColor || "#ffffff",
      },
      files,
      maxWidthOrHeight: 400, // Reasonable size for thumbnails
      getDimensions: () => ({ width: 400, height: 300, scale: 1 }),
    });

    // Convert blob to base64 data URL
    return new Promise((resolve) => {
      const reader = new FileReader();
      reader.onloadend = () => resolve(reader.result as string);
      reader.onerror = () => resolve(null);
      reader.readAsDataURL(blob);
    });
  } catch (error) {
    console.warn("Failed to generate thumbnail:", error);
    return null;
  }
}

export function BoardEditor({
  boardId,
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  onTitleChange,
  viewMode = false,
  onViewModeChange,
  preloadedBoard,
  shareToken,
}: BoardEditorProps) {
  const { user } = useApp();
  const [board, setBoard] = useState<BoardWithScene | null>(null);
  const [saveStatus, setSaveStatus] = useState<SaveStatus>("idle");
  const [lastSaved, setLastSaved] = useState<string | null>(null);
  const [showHistory, setShowHistory] = useState(false);
  const [showMarkdownEditor, setShowMarkdownEditor] = useState(false);
  const [editingMarkdownElementId, setEditingMarkdownElementId] = useState<
    string | null
  >(null);
  const [editingMarkdownContent, setEditingMarkdownContent] = useState("");

  // Rich text card editor state
  const [showRichTextEditor, setShowRichTextEditor] = useState(false);
  const [editingRichTextElementId, setEditingRichTextElementId] = useState<
    string | null
  >(null);
  const [editingRichTextContent, setEditingRichTextContent] = useState("");

  const [initialData, setInitialData] = useState<{
    elements: ExcalidrawElements;
    appState: ExcalidrawAppState;
    files: BinaryFiles;
  } | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [storageSize, setStorageSize] = useState<string | null>(null);

  // Restore version confirmation modal
  const [showRestoreModal, setShowRestoreModal] = useState(false);
  const [versionToRestore, setVersionToRestore] = useState<BoardVersion | null>(
    null
  );
  const [restoring, setRestoring] = useState(false);

  const excalidrawRef = useRef<ExcalidrawAPI | null>(null);
  const lastSavedEtagRef = useRef<string>("");
  const hasUnsavedChangesRef = useRef(false);
  const lastSavedHashRef = useRef<string>("");
  const searchTextMigrationDoneRef = useRef(false);
  const lastZoomRef = useRef<number>(1);
  const zoomCorrectionTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  // Debounce timer for card operations to prevent save storms
  const cardSaveDebounceRef = useRef<NodeJS.Timeout | null>(null);
  // Debounce timer for intermediate WS broadcasts (real-time sync between saves)
  const wsBroadcastDebounceRef = useRef<NodeJS.Timeout | null>(null);
  // Track last broadcast hash to avoid redundant broadcasts
  const lastBroadcastHashRef = useRef<string>("");
  // Track if user was editing text (to trigger save when they finish)
  const wasEditingTextRef = useRef(false);

  // WebSocket / live cursors
  const wsClientRef = useRef<WSClient | null>(null);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [collaborators, setCollaborators] = useState<Map<string, any>>(
    () => new Map()
  );
  // Current user ID ref for filtering self-cursors inside WS callback
  const currentUserIdRef = useRef<string | undefined>(user?.id);
  useEffect(() => { currentUserIdRef.current = user?.id; }, [user?.id]);
  // Ref for latest collaborators — used in WS callback to re-push after scene updates.
  // Updated synchronously inside setCollaborators() callbacks for immediate consistency.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const collaboratorsRef = useRef<Map<string, any>>(collaborators);

  /**
   * Limits zoom level during search navigation to prevent extreme zoom.
   *
   * Excalidraw zooms to fit the matched search text element. Since our search text
   * elements use fontSize: 1 (to minimize yellow highlight visibility), the automatic
   * zoom can reach extreme levels (1400%+). This function detects that scenario and
   * resets zoom to 100% after a brief delay, providing a better UX.
   *
   * @param appState - Current Excalidraw application state containing zoom and search info
   */
  const limitSearchZoom = useCallback((appState: ExcalidrawAppState) => {
    if (!excalidrawRef.current) return;

    const currentZoom = appState.zoom?.value || 1;

    // Detect if we just did a search navigation (zoom jumped significantly above 100%)
    const hasActiveSearch =
      appState.searchMatches && appState.searchMatches.length > 0;

    // Limit zoom if it's way too high during active search
    if (hasActiveSearch && currentZoom > 3) {
      // Clear any pending correction
      if (zoomCorrectionTimeoutRef.current) {
        clearTimeout(zoomCorrectionTimeoutRef.current);
      }

      // Schedule zoom correction
      zoomCorrectionTimeoutRef.current = setTimeout(() => {
        if (!excalidrawRef.current) return;
        excalidrawRef.current.updateScene({
          appState: {
            zoom: { value: 1 as 0.1 },
          },
        });
      }, 50);
    }

    lastZoomRef.current = currentZoom;
  }, []);

  /**
   * Migrates search text elements to ensure they're properly positioned and configured.
   *
   * Search text elements are invisible text elements grouped with markdown/rich text cards.
   * They enable Excalidraw's built-in search to find card content. This migration:
   *
   * 1. Positions search text at the same location as parent card (for proper navigation)
   * 2. Creates missing search text elements for legacy cards
   * 3. Removes orphaned search text elements (cards that were deleted)
   * 4. Sets fontSize: 1 to minimize the yellow highlight box Excalidraw draws
   *
   * @param api - Excalidraw API instance for scene manipulation
   */
  const migrateSearchTextElements = useCallback((api: ExcalidrawAPI) => {
    if (searchTextMigrationDoneRef.current) return;

    const elements = api.getSceneElements();
    let needsUpdate = false;
    const updatedElements = elements.map((el) => {
      // Check if this is a markdown or rich text search text element
      // Check by customData OR by ID pattern
      const isSearchText =
        el.customData?.isMarkdownSearchText ||
        el.customData?.isRichTextSearchText ||
        el.id?.startsWith("rtsearch-") ||
        el.id?.startsWith("mdsearch-");
      if (!isSearchText) return el;

      // Find the parent card - try customData first, then ID pattern
      let parentId =
        el.customData?.parentMarkdownCardId ||
        el.customData?.parentRichTextCardId;

      // If no customData parent, derive from ID
      if (!parentId && el.id?.startsWith("rtsearch-")) {
        parentId = el.id.replace("rtsearch-", "");
      } else if (!parentId && el.id?.startsWith("mdsearch-")) {
        parentId = el.id.replace("mdsearch-", "");
      }

      const parentCard = parentId
        ? elements.find((e) => e.id === parentId)
        : null;

      if (!parentCard) return el;

      // Position search text at same location as parent card
      const idealX = parentCard.x;
      const idealY = parentCard.y;

      // Check if element needs migration (use small tolerance)
      const needsPositionFix =
        Math.abs(el.x - idealX) > 1 || Math.abs(el.y - idealY) > 1;
      const needsSizeFix =
        Math.abs(el.width - parentCard.width) > 1 ||
        Math.abs(el.height - parentCard.height) > 1;

      if (needsPositionFix || needsSizeFix) {
        needsUpdate = true;
        return {
          ...el,
          x: idealX,
          y: idealY,
          width: parentCard.width,
          height: parentCard.height,
          fontSize: 1, // Tiny font so yellow highlight is nearly invisible
          version: (el.version || 1) + 1,
          updated: Date.now(),
        };
      }
      return el;
    });

    // Also check for rich text/markdown cards that are missing search text elements
    // and create them
    const cardsNeedingSearchText: typeof updatedElements = [];
    updatedElements.forEach((el) => {
      const isRichTextCard =
        el.customData?.isRichTextCard || el.link?.startsWith("richtext://");
      const isMarkdownCard =
        el.customData?.isMarkdownCard || el.link?.startsWith("markdown://");

      if (isRichTextCard || isMarkdownCard) {
        // Check if this card has a corresponding search text element
        const searchTextId =
          el.customData?.searchTextElementId ||
          (isRichTextCard ? `rtsearch-${el.id}` : `mdsearch-${el.id}`);
        const hasSearchText = updatedElements.some(
          (e) =>
            e.id === searchTextId ||
            e.customData?.parentRichTextCardId === el.id ||
            e.customData?.parentMarkdownCardId === el.id
        );

        if (!hasSearchText) {
          // Create a search text element for this card
          const seed = Math.floor(Math.random() * 2000000000);
          const groupId = el.groupIds?.[0] || `group-${el.id}`;

          // Extract searchable text from card content
          let searchableText = "";
          if (isRichTextCard && el.customData?.richTextContent) {
            try {
              const content = JSON.parse(el.customData.richTextContent);
              type TiptapNode = { text?: string; content?: TiptapNode[] };
              const extractText = (node: TiptapNode): string => {
                if (node.text) return node.text;
                if (node.content)
                  return node.content.map(extractText).join(" ");
                return "";
              };
              searchableText = extractText(content as TiptapNode);
            } catch {
              searchableText = "Rich text card";
            }
          } else if (isMarkdownCard && el.customData?.markdown) {
            searchableText = el.customData.markdown.replace(
              /[#*_`~\[\]()]/g,
              " "
            );
          }

          const newSearchTextElement = {
            id: searchTextId,
            type: "text" as const,
            x: el.x,
            y: el.y,
            width: el.width,
            height: el.height,
            angle: 0,
            strokeColor: "transparent",
            backgroundColor: "transparent",
            fillStyle: "solid" as const,
            strokeWidth: 0,
            strokeStyle: "solid" as const,
            roughness: 0,
            opacity: 0,
            groupIds: [groupId],
            frameId: null,
            index: null,
            roundness: null,
            seed: seed,
            version: 1,
            versionNonce: seed,
            isDeleted: false,
            boundElements: null,
            updated: Date.now(),
            link: null,
            locked: true,
            text: searchableText || "Card content",
            originalText: searchableText || "Card content",
            fontSize: 1,
            fontFamily: 1,
            textAlign: "left" as const,
            verticalAlign: "top" as const,
            containerId: null,
            lineHeight: 1.25,
            autoResize: false,
            customData: isRichTextCard
              ? { isRichTextSearchText: true, parentRichTextCardId: el.id }
              : { isMarkdownSearchText: true, parentMarkdownCardId: el.id },
          };

          cardsNeedingSearchText.push(
            newSearchTextElement as (typeof updatedElements)[0]
          );
          needsUpdate = true;
        }
      }
    });

    if (cardsNeedingSearchText.length > 0) {
      updatedElements.push(...cardsNeedingSearchText);
    }

    // Clean up: remove orphaned search text elements (no parent card)
    // and ensure all search text elements are positioned correctly
    const finalElements = updatedElements.filter((el) => {
      // Check if this is a search text element
      const isSearchText =
        el.customData?.isMarkdownSearchText ||
        el.customData?.isRichTextSearchText ||
        el.id?.startsWith("rtsearch-") ||
        el.id?.startsWith("mdsearch-");

      if (!isSearchText) return true; // Keep non-search elements

      // Find parent card
      let parentId =
        el.customData?.parentMarkdownCardId ||
        el.customData?.parentRichTextCardId;
      if (!parentId && el.id?.startsWith("rtsearch-")) {
        parentId = el.id.replace("rtsearch-", "");
      } else if (!parentId && el.id?.startsWith("mdsearch-")) {
        parentId = el.id.replace("mdsearch-", "");
      }

      const parentCard = parentId
        ? updatedElements.find((e) => e.id === parentId)
        : null;

      // Remove orphaned search text elements
      if (!parentCard) {
        needsUpdate = true;
        return false;
      }

      return true;
    });

    if (needsUpdate) {
      api.updateScene({ elements: finalElements });
      hasUnsavedChangesRef.current = true;
    }

    searchTextMigrationDoneRef.current = true;
  }, []);

  // Helper: extract initial data from a board response (used by both authenticated and shared paths)
  const applyBoardData = useCallback(
    (boardData: BoardWithScene) => {
      setBoard(boardData);
      lastSavedEtagRef.current = boardData.etag || "";

      const latestVersion = boardData.latestVersion;

      if (latestVersion) {
        const sceneJson = latestVersion.sceneJson as {
          elements?: ExcalidrawElements;
          files?: BinaryFiles;
        };
        const files = sceneJson.files || {};

        // Sanitize elements: fix or remove corrupted entries that would crash Excalidraw.
        // A backend bug (now fixed) in cleanOrphanedFiles could strip all element properties
        // down to just {type, text}, losing x/y/width/height/points etc.
        const pointBasedTypes = new Set(["line", "arrow", "freedraw"]);
        const rawElements = (sceneJson.elements || []).filter((el) => {
          // Drop elements completely missing geometry (sign of data-loss corruption)
          if (el.type && el.x === undefined && el.y === undefined) {
            console.warn(`Dropping corrupted element (no geometry):`, el.type, el.id);
            return false;
          }
          // Drop line/arrow/freedraw missing required points array
          if (pointBasedTypes.has(el.type) && !Array.isArray(el.points)) {
            console.warn(`Dropping corrupted ${el.type} element (missing points):`, el.id);
            return false;
          }
          return true;
        });

        // Migrate search text elements inline before setting initial data
        const elements = rawElements.map((el) => {
          const isSearchText =
            el.customData?.isMarkdownSearchText ||
            el.customData?.isRichTextSearchText ||
            el.id?.startsWith("rtsearch-") ||
            el.id?.startsWith("mdsearch-");
          if (!isSearchText) return el;

          let parentId =
            el.customData?.parentMarkdownCardId ||
            el.customData?.parentRichTextCardId;
          if (!parentId && el.id?.startsWith("rtsearch-")) {
            parentId = el.id.replace("rtsearch-", "");
          } else if (!parentId && el.id?.startsWith("mdsearch-")) {
            parentId = el.id.replace("mdsearch-", "");
          }

          const parentCard = parentId
            ? rawElements.find((e) => e.id === parentId)
            : null;
          if (!parentCard) return el;

          const idealX = parentCard.x;
          const idealY = parentCard.y;
          const needsFix =
            Math.abs(el.x - idealX) > 1 ||
            Math.abs(el.y - idealY) > 1 ||
            Math.abs(el.width - parentCard.width) > 1 ||
            Math.abs(el.height - parentCard.height) > 1;

          if (needsFix) {
            return {
              ...el,
              x: idealX,
              y: idealY,
              width: parentCard.width,
              height: parentCard.height,
              fontSize: 1,
              version: (el.version || 1) + 1,
              updated: Date.now(),
            };
          }
          return el;
        });

        setInitialData({
          elements,
          appState: latestVersion.appStateJson || {},
          files,
        });
        setLastSaved(latestVersion.createdAt);
        lastSavedHashRef.current = hashSceneContent(elements, files);
      } else {
        setInitialData({ elements: [], appState: {}, files: {} });
        lastSavedHashRef.current = hashSceneContent([], {});
      }
    },
    []
  );

  // Load board and initial data from API (or use preloaded data for shared boards)
  useEffect(() => {
    if (preloadedBoard) {
      applyBoardData(preloadedBoard);
      return;
    }

    const loadBoard = async () => {
      try {
        const boardData = await boardApi.get(boardId);
        applyBoardData(boardData);
      } catch (error) {
        console.error("Failed to load board:", error);
        setLoadError(
          error instanceof ApiError ? error.message : "Failed to load board"
        );
      }
    };

    loadBoard();
  }, [boardId, preloadedBoard, applyBoardData]);

  // Fetch storage info for this board
  const fetchStorageInfo = useCallback(async () => {
    try {
      const data = await boardApi.getStorage(boardId);
      const bytes = data.totalBytes || 0;
      const formatted =
        bytes < 1024
          ? `${bytes} B`
          : bytes < 1048576
            ? `${(bytes / 1024).toFixed(1)} KB`
            : `${(bytes / 1048576).toFixed(1)} MB`;
      setStorageSize(formatted);
    } catch (error) {
      console.warn("Failed to fetch storage info:", error);
    }
  }, [boardId]);

  // Load storage info when board loads and after saves (skip for shared/anonymous)
  useEffect(() => {
    if (board && !preloadedBoard) {
      const timeoutId = setTimeout(() => fetchStorageInfo(), 0);
      return () => clearTimeout(timeoutId);
    }
  }, [board, fetchStorageInfo, preloadedBoard]);

  // WebSocket connection for live cursors / presence
  useEffect(() => {
    if (!board) return;

    // Determine auth: use share token for anonymous, JWT cookie for authenticated users
    const opts: ConstructorParameters<typeof WSClient>[0] = {
      boardId: board.id,
      onEvent: (type: WSEventType, payload: unknown) => {
        if (type === "welcome") {
          // Server tells us our own identity — critical for share-token users
          // whose userId is server-assigned ("anon-<linkId>").
          const data = payload as WelcomePayload;
          if (data.viewer) {
            currentUserIdRef.current = data.viewer.userId;
            // Remove self from collaborators if presence arrived before welcome
            setCollaborators((prev) => {
              if (!prev.has(data.viewer.userId)) return prev;
              const next = new Map(prev);
              next.delete(data.viewer.userId);
              collaboratorsRef.current = next;
              return next;
            });
          }
        } else if (type === "cursor_update") {
          // Process cursor updates for all connected users so viewers can
          // see editors' cursor positions in real time.
          const cursors = Array.isArray(payload)
            ? (payload as CursorPayload[])
            : [payload as CursorPayload];
          const uid = currentUserIdRef.current;
          setCollaborators((prev) => {
            const next = new Map(prev);
            for (const cursor of cursors) {
              // Skip own cursor (broadcast includes sender)
              if (uid && cursor.userId === uid) continue;
              next.set(cursor.userId, {
                username: cursor.name,
                pointer: { x: cursor.x, y: cursor.y, tool: "pointer" },
                color: { background: cursor.color + "33", stroke: cursor.color },
                isCurrentUser: false,
              });
            }
            // Keep ref in sync immediately (not waiting for React render)
            collaboratorsRef.current = next;
            return next;
          });
        } else if (type === "presence") {
          // Show presence for all users (viewers see who else is editing)
          const presence = payload as PresencePayload;
          if (presence.viewers) {
            const uid = currentUserIdRef.current;
            setCollaborators((prev) => {
              const next = new Map(prev);
              const remote = presence.viewers.filter((v: ViewerInfo) => !uid || v.userId !== uid);
              const activeIds = new Set(remote.map((v: ViewerInfo) => v.userId));
              for (const key of prev.keys()) {
                if (!activeIds.has(key)) next.delete(key);
              }
              for (const v of remote) {
                if (!next.has(v.userId)) {
                  next.set(v.userId, {
                    username: v.name,
                    color: { background: (v.color || "#aaa") + "33", stroke: v.color || "#aaa" },
                    isCurrentUser: false,
                  });
                }
              }
              collaboratorsRef.current = next;
              return next;
            });
          }
        } else if (type === "joined") {
          // Show join events for all users
          const data = payload as { viewer: ViewerInfo };
          const uid = currentUserIdRef.current;
          if (data.viewer && (!uid || data.viewer.userId !== uid)) {
            setCollaborators((prev) => {
              const next = new Map(prev);
              next.set(data.viewer.userId, {
                username: data.viewer.name,
                color: { background: (data.viewer.color || "#aaa") + "33", stroke: data.viewer.color || "#aaa" },
                isCurrentUser: false,
              });
              collaboratorsRef.current = next;
              return next;
            });
          }
        } else if (type === "left") {
          // Show leave events for all users
          const data = payload as { userId: string };
          if (data.userId) {
            setCollaborators((prev) => {
              const next = new Map(prev);
              next.delete(data.userId);
              collaboratorsRef.current = next;
              return next;
            });
          }
        } else if (type === "scene_update") {
          // Another user updated the scene — apply their changes to our Excalidraw
          const data = payload as { elements?: ExcalidrawElements; files?: BinaryFiles };
          if (data && excalidrawRef.current) {
            if (data.elements) {
              // Sanitize incoming elements to prevent crash on corrupted data
              const ptTypes = new Set(["line", "arrow", "freedraw"]);
              const safeElements = data.elements.filter(
                (el) => (el.x !== undefined || el.y !== undefined) &&
                  (!ptTypes.has(el.type) || Array.isArray(el.points))
              );
              // Always combine elements and collaborators into a single updateScene
              // call. Excalidraw 0.18+ resets the cursor rendering layer during
              // element reconciliation; re-supplying collaborators prevents that.
              const sceneUpdate: Parameters<ExcalidrawAPI["updateScene"]>[0] = {
                elements: safeElements,
              };
              const currentCollabs = collaboratorsRef.current;
              if (currentCollabs.size > 0) {
                sceneUpdate.collaborators = currentCollabs;
              }
              excalidrawRef.current.updateScene(sceneUpdate);
            }
            if (data.files && Object.keys(data.files).length > 0) {
              excalidrawRef.current.addFiles(Object.values(data.files));
            }
            // Update our saved hash so we don't re-save their changes as our own
            if (data.elements) {
              lastSavedHashRef.current = hashSceneContent(
                data.elements,
                data.files || excalidrawRef.current.getFiles()
              );
              hasUnsavedChangesRef.current = false;
            }
          }
        }
      },
    };

    if (shareToken) {
      opts.shareToken = shareToken;
    }
    // Authenticated users rely on the cookie-based JWT; the WS handler reads
    // the token from query param. We don't have raw access to the cookie value
    // from JS (httpOnly), so for authenticated users the backend needs to also
    // accept cookie auth for WS. For now, share-token path is the priority.

    const client = new WSClient(opts);
    client.connect();
    wsClientRef.current = client;

    return () => {
      client.disconnect();
      wsClientRef.current = null;
      if (wsBroadcastDebounceRef.current) {
        clearTimeout(wsBroadcastDebounceRef.current);
      }
    };
  }, [board, shareToken]);

  // Push collaborator map updates into Excalidraw
  useEffect(() => {
    if (excalidrawRef.current && collaborators.size >= 0) {
      excalidrawRef.current.updateScene({
        collaborators,
      });
    }
  }, [collaborators]);

  // Send cursor position on pointer move (throttled to ~30fps to stay within WS rate limits)
  const lastCursorSendRef = useRef(0);
  const handlePointerUpdate = useCallback(
    (payload: { pointer: { x: number; y: number }; button: string }) => {
      const now = Date.now();
      if (now - lastCursorSendRef.current < 33) return; // throttle to ~30fps
      lastCursorSendRef.current = now;
      wsClientRef.current?.sendCursorMove(payload.pointer.x, payload.pointer.y);
    },
    []
  );

  // Save to server via API
  const saveToServer = useCallback(
    async (
      elements: ExcalidrawElements,
      appState: ExcalidrawAppState,
      files: BinaryFiles
    ) => {
      if (!board || !user) return;

      // Skip save if content hasn't actually changed (prevents growing board size)
      const currentHash = hashSceneContent(elements, files);
      if (currentHash === lastSavedHashRef.current) {
        hasUnsavedChangesRef.current = false;
        setSaveStatus("saved");
        setTimeout(() => setSaveStatus("idle"), 1500);
        return;
      }

      setSaveStatus("saving");

      try {
        // Generate thumbnail in parallel (don't block save on it)
        const thumbnailPromise = generateThumbnail(elements, appState, files);

        // Start save immediately, thumbnail will be included if ready
        const thumbnail = await thumbnailPromise;

        const result = await boardApi.saveVersion(board.id, {
          sceneJson: { elements: [...elements], files },
          appStateJson: stripVolatileAppState(appState),
          expectedEtag: lastSavedEtagRef.current || undefined,
          thumbnail: thumbnail || undefined,
        });

        // Check for conflicts
        if (result.conflict) {
          setSaveStatus("conflict");
          return;
        }

        // Update our etag reference and saved hash
        lastSavedEtagRef.current = result.etag;
        lastSavedHashRef.current = hashSceneContent(elements, files);
        lastBroadcastHashRef.current = lastSavedHashRef.current;
        hasUnsavedChangesRef.current = false;

        setSaveStatus("saved");
        setLastSaved(result.version.createdAt);

        // Broadcast scene update to other connected clients (viewers, shared users)
        // NOTE: Only send elements, NOT files — files contain base64 image data
        // that easily exceeds WS_MAX_MESSAGE_SIZE (64KB default) and would crash
        // the WebSocket connection. Files are already persisted via the save API
        // and viewers fetch them on load / via the file endpoint.
        wsClientRef.current?.sendSceneUpdate({ elements: [...elements] });

        // Refresh storage info after save
        fetchStorageInfo();

        // Reset to idle after a bit
        setTimeout(() => setSaveStatus("idle"), 2000);
      } catch (error) {
        console.error("Failed to save:", error);

        // Handle conflict from 409 response
        if (error instanceof ApiError && error.status === 409) {
          setSaveStatus("conflict");
        } else {
          setSaveStatus("error");
        }
      }
    },
    [board, user, fetchStorageInfo]
  );

  // Interval-based autosave: save every 10 seconds IF there are unsaved changes
  useEffect(() => {
    if (!board || !user || viewMode) return;

    const intervalId = setInterval(() => {
      // Only save if there are unsaved changes and we have the excalidraw ref
      if (hasUnsavedChangesRef.current && excalidrawRef.current) {
        const elements = excalidrawRef.current.getSceneElements();
        const appState = excalidrawRef.current.getAppState();
        const files = excalidrawRef.current.getFiles();
        saveToServer(elements, appState, files);
      }
    }, AUTOSAVE_INTERVAL);

    return () => clearInterval(intervalId);
  }, [board, user, saveToServer, viewMode]);

  // Handle changes from Excalidraw - only marks dirty if content actually changed
  const handleChange = useCallback(
    (
      elements: ExcalidrawElements,
      appState: ExcalidrawAppState,
      files: BinaryFiles
    ) => {
      if (!board) return;

      // Limit zoom when search navigation causes extreme zoom levels
      limitSearchZoom(appState);

      // Compare current scene hash with last saved hash
      const currentHash = hashSceneContent(elements, files);
      if (currentHash !== lastSavedHashRef.current) {
        hasUnsavedChangesRef.current = true;
      }

      // Debounced intermediate WS broadcast for real-time sync.
      // This sends element changes to other viewers within ~1s, without
      // waiting for the 10s autosave. Only elements are sent (no files)
      // to stay under WS message size limits.
      if (!viewMode && currentHash !== lastBroadcastHashRef.current) {
        if (wsBroadcastDebounceRef.current) {
          clearTimeout(wsBroadcastDebounceRef.current);
        }
        wsBroadcastDebounceRef.current = setTimeout(() => {
          if (!excalidrawRef.current || !wsClientRef.current) return;
          const latestElements = excalidrawRef.current.getSceneElements();
          const latestHash = hashSceneContent(
            latestElements,
            excalidrawRef.current.getFiles()
          );
          if (latestHash !== lastBroadcastHashRef.current) {
            lastBroadcastHashRef.current = latestHash;
            wsClientRef.current.sendSceneUpdate({
              elements: [...latestElements],
            });
          }
        }, WS_BROADCAST_INTERVAL);
      }

      // Detect when user finishes editing text and trigger debounced save
      // editingElement is set while user is actively editing text, null when done
      const isCurrentlyEditing = appState.editingElement !== null;

      if (
        wasEditingTextRef.current &&
        !isCurrentlyEditing &&
        hasUnsavedChangesRef.current
      ) {
        // User just finished editing - trigger debounced save
        if (cardSaveDebounceRef.current) {
          clearTimeout(cardSaveDebounceRef.current);
        }
        cardSaveDebounceRef.current = setTimeout(() => {
          if (!excalidrawRef.current) return;
          const latestElements = excalidrawRef.current.getSceneElements();
          const latestAppState = excalidrawRef.current.getAppState();
          const latestFiles = excalidrawRef.current.getFiles();
          saveToServer(latestElements, latestAppState, latestFiles);
        }, 300);
      }

      wasEditingTextRef.current = isCurrentlyEditing;
    },
    [board, viewMode, limitSearchZoom, saveToServer]
  );

  // Manual save
  const handleManualSave = useCallback(() => {
    if (!excalidrawRef.current) return;
    const elements = excalidrawRef.current.getSceneElements();
    const appState = excalidrawRef.current.getAppState();
    const files = excalidrawRef.current.getFiles();
    saveToServer(elements, appState, files);
  }, [saveToServer]);

  // Restore version - open confirmation modal
  const handleRestoreVersion = useCallback((version: BoardVersion) => {
    setVersionToRestore(version);
    setShowRestoreModal(true);
  }, []);

  // Restore version - confirm and execute
  const confirmRestoreVersion = useCallback(async () => {
    if (!excalidrawRef.current || !user || !board || !versionToRestore) return;

    setRestoring(true);
    try {
      // Restore via API (this creates a new version from the old one)
      const result = await boardApi.restoreVersion(
        board.id,
        versionToRestore.version
      );

      // The version list doesn't include sceneJson (it's metadata only).
      // Fetch the full board to get the restored scene data.
      const restoredBoard = await boardApi.get(board.id);
      const latestVersion = restoredBoard.latestVersion;
      const sceneJson = latestVersion?.sceneJson as {
        elements?: ExcalidrawElements;
        files?: BinaryFiles;
      } | undefined;

      if (sceneJson) {
        // Sanitize elements before applying
        const pointBasedTypes = new Set(["line", "arrow", "freedraw"]);
        const sanitizedElements = (sceneJson.elements || []).filter((el) => {
          if (el.type && el.x === undefined && el.y === undefined) return false;
          if (pointBasedTypes.has(el.type) && !Array.isArray(el.points)) return false;
          return true;
        });

        excalidrawRef.current.updateScene({
          elements: sanitizedElements,
          appState: latestVersion?.appStateJson || undefined,
        });

        if (sceneJson.files && Object.keys(sceneJson.files).length > 0) {
          excalidrawRef.current.addFiles(Object.values(sceneJson.files));
        }
      }

      // Update etag and board state
      lastSavedEtagRef.current = result.etag;
      lastSavedHashRef.current = hashSceneContent(
        excalidrawRef.current.getSceneElements(),
        excalidrawRef.current.getFiles()
      );
      hasUnsavedChangesRef.current = false;

      setShowRestoreModal(false);
      setVersionToRestore(null);
      setShowHistory(false);
      setSaveStatus("saved");
      setLastSaved(result.version.createdAt);

      // Refresh storage info after restore
      fetchStorageInfo();
      toast("Version restored", {
        description: `Restored to version ${versionToRestore.version}`,
      });
    } catch (error) {
      console.error("Failed to restore version:", error);
      toast.error("Failed to restore version", {
        description:
          error instanceof ApiError ? error.message : "Please try again",
      });
    } finally {
      setRestoring(false);
    }
  }, [user, board, versionToRestore, fetchStorageInfo]);

  // Handle editing a markdown card (triggered by double-click)
  const handleEditMarkdownCard = useCallback(
    (elementId: string, markdown: string) => {
      setEditingMarkdownElementId(elementId);
      setEditingMarkdownContent(markdown);
      setShowMarkdownEditor(true);
    },
    []
  );

  // Save markdown card content
  const handleSaveMarkdownCard = useCallback(
    (newMarkdown: string) => {
      if (!excalidrawRef.current || !editingMarkdownElementId) return;

      const elements = excalidrawRef.current.getSceneElements();
      const searchableText = stripMarkdownToPlainText(newMarkdown);

      // Find the markdown card to get its search text element ID
      const markdownCard = elements.find(
        (el) => el.id === editingMarkdownElementId
      );
      const searchTextElementId = markdownCard?.customData?.searchTextElementId;

      const updatedElements = elements.map((el) => {
        // Update the markdown card
        if (el.id === editingMarkdownElementId) {
          return {
            ...el,
            customData: {
              ...el.customData,
              markdown: newMarkdown,
            },
            // Bump version to trigger re-render
            version: (el.version || 1) + 1,
            updated: Date.now(),
          };
        }
        // Update the linked search text element
        if (searchTextElementId && el.id === searchTextElementId) {
          return {
            ...el,
            text: searchableText,
            originalText: searchableText,
            version: (el.version || 1) + 1,
            updated: Date.now(),
          };
        }
        return el;
      });

      excalidrawRef.current.updateScene({ elements: updatedElements });
      hasUnsavedChangesRef.current = true;

      // Trigger immediate save to persist card content changes
      const appState = excalidrawRef.current.getAppState();
      const files = excalidrawRef.current.getFiles();
      saveToServer(updatedElements as ExcalidrawElements, appState, files);

      setEditingMarkdownElementId(null);
      setEditingMarkdownContent("");
    },
    [editingMarkdownElementId, saveToServer]
  );

  // Handle editing a rich text card (triggered by double-click)
  const handleEditRichTextCard = useCallback(
    (elementId: string, content: string) => {
      setEditingRichTextElementId(elementId);
      setEditingRichTextContent(content);
      setShowRichTextEditor(true);
    },
    []
  );

  // Extract plain text from Tiptap JSON for search indexing
  const extractTextFromTiptapJson = useCallback((json: object): string => {
    const extractText = (node: {
      type?: string;
      text?: string;
      content?: object[];
    }): string => {
      if (node.text) return node.text;
      if (node.content) {
        return node.content.map(extractText).join(" ");
      }
      return "";
    };
    return extractText(
      json as { type?: string; text?: string; content?: object[] }
    ).trim();
  }, []);

  /**
   * Saves updated content to a rich text card and syncs the search text element.
   *
   * When a user finishes editing a rich text card, this function:
   * 1. Updates the card's customData with the new Tiptap JSON content
   * 2. Extracts plain text from the JSON for search indexing
   * 3. Updates the associated search text element with the extracted text
   * 4. Triggers autosave via hasUnsavedChangesRef
   *
   * @param newContent - Tiptap JSON content as a string
   */
  const handleSaveRichTextCard = useCallback(
    (newContent: string) => {
      if (!excalidrawRef.current || !editingRichTextElementId) return;

      const elements = excalidrawRef.current.getSceneElements();

      // Extract searchable text from JSON content
      let searchableText = "";
      try {
        const parsed = JSON.parse(newContent);
        searchableText = extractTextFromTiptapJson(parsed);
      } catch {
        searchableText = "Rich Text Content";
      }

      // Find the rich text card to get its search text element ID
      const richTextCard = elements.find(
        (el) => el.id === editingRichTextElementId
      );
      const searchTextElementId = richTextCard?.customData?.searchTextElementId;

      const updatedElements = elements.map((el) => {
        // Update the rich text card
        if (el.id === editingRichTextElementId) {
          return {
            ...el,
            customData: {
              ...el.customData,
              richTextContent: newContent,
            },
            // Bump version to trigger re-render
            version: (el.version || 1) + 1,
            updated: Date.now(),
          };
        }
        // Update the linked search text element
        if (searchTextElementId && el.id === searchTextElementId) {
          return {
            ...el,
            text: searchableText,
            originalText: searchableText,
            version: (el.version || 1) + 1,
            updated: Date.now(),
          };
        }
        return el;
      });

      excalidrawRef.current.updateScene({ elements: updatedElements });
      hasUnsavedChangesRef.current = true;

      // Trigger immediate save to persist card content changes
      const appState = excalidrawRef.current.getAppState();
      const files = excalidrawRef.current.getFiles();
      saveToServer(updatedElements as ExcalidrawElements, appState, files);

      setEditingRichTextElementId(null);
      setEditingRichTextContent("");
    },
    [editingRichTextElementId, extractTextFromTiptapJson, saveToServer]
  );

  /**
   * Inserts a new markdown card with Mermaid diagram support at the center of the viewport.
   *
   * Creates two elements:
   * 1. An embeddable element with markdown:// link (displays the MarkdownCard component)
   * 2. A hidden search text element (enables Excalidraw search to find card content)
   *
   * Both elements are grouped together and the card opens in edit mode immediately.
   * The search text element uses fontSize: 1 to minimize yellow highlight visibility.
   */
  const handleInsertMarkdownCard = useCallback(() => {
    if (!excalidrawRef.current) return;

    const appState = excalidrawRef.current.getAppState();
    const scrollX = appState.scrollX || 0;
    const scrollY = appState.scrollY || 0;
    const zoom = appState.zoom?.value || 1;
    const viewportWidth = appState.width || 800;
    const viewportHeight = appState.height || 600;

    // Calculate center in scene coordinates
    const centerX = -scrollX + viewportWidth / 2 / zoom;
    const centerY = -scrollY + viewportHeight / 2 / zoom;

    const cardWidth = 400;
    const cardHeight = 300;
    const seed = Math.floor(Math.random() * 2000000000);
    const elementId = `md-${Date.now()}-${Math.random()
      .toString(36)
      .slice(2, 9)}`;
    const searchTextId = `mdsearch-${elementId}`;
    const groupId = `mdgroup-${elementId}`;

    const defaultMarkdown =
      "# New Markdown Card\n\nDouble-click to edit this card.\n\n## Features\n\n- **Bold** and *italic* text\n- Lists and tables\n- Code blocks\n- Mermaid diagrams\n\n```mermaid\ngraph LR\n    A[Start] --> B[End]\n```";
    const searchableText = stripMarkdownToPlainText(defaultMarkdown);

    // Create embeddable element for markdown card
    const markdownElement = {
      id: elementId,
      type: "embeddable" as const,
      x: centerX - cardWidth / 2,
      y: centerY - cardHeight / 2,
      width: cardWidth,
      height: cardHeight,
      angle: 0,
      strokeColor: "#1e1e1e",
      backgroundColor: "#ffffff",
      fillStyle: "solid" as const,
      strokeWidth: 1,
      strokeStyle: "solid" as const,
      roughness: 0,
      opacity: 100,
      groupIds: [groupId],
      frameId: null,
      index: null,
      roundness: { type: 3 },
      seed: seed,
      version: 1,
      versionNonce: seed,
      isDeleted: false,
      boundElements: null,
      updated: Date.now(),
      link: `markdown://${elementId}`,
      locked: false,
      customData: {
        markdown: defaultMarkdown,
        isMarkdownCard: true,
        searchTextElementId: searchTextId,
      },
    };

    // Create a hidden text element for search indexing
    // This text element is grouped with the markdown card and contains plain text version
    // Positioned at same location as card for proper search navigation
    const searchTextElement = {
      id: searchTextId,
      type: "text" as const,
      x: centerX - cardWidth / 2, // Same position as card
      y: centerY - cardHeight / 2,
      width: cardWidth, // Match card width for proper zoom on search navigation
      height: cardHeight, // Match card height for proper zoom on search navigation
      angle: 0,
      strokeColor: "transparent",
      backgroundColor: "transparent",
      fillStyle: "solid" as const,
      strokeWidth: 0,
      strokeStyle: "solid" as const,
      roughness: 0,
      opacity: 0, // Invisible
      groupIds: [groupId],
      frameId: null,
      index: null,
      roundness: null,
      seed: seed + 1,
      version: 1,
      versionNonce: seed + 1,
      isDeleted: false,
      boundElements: null,
      updated: Date.now(),
      link: null,
      locked: true,
      text: searchableText,
      originalText: searchableText,
      fontSize: 1, // Normal font for proper zoom to minimize highlight box
      fontFamily: 1,
      textAlign: "left" as const,
      verticalAlign: "top" as const,
      containerId: null,
      lineHeight: 1.25,
      autoResize: false,
      customData: {
        isMarkdownSearchText: true,
        parentMarkdownCardId: elementId,
      },
    };

    const currentElements = excalidrawRef.current.getSceneElements();
    const newElements = [
      ...currentElements,
      markdownElement,
      searchTextElement,
    ];
    excalidrawRef.current.updateScene({
      elements: newElements,
    });

    hasUnsavedChangesRef.current = true;

    // Debounced save to prevent save storms when rapidly inserting cards
    // Uses 300ms debounce - fast enough to feel instant, slow enough to batch
    if (cardSaveDebounceRef.current) {
      clearTimeout(cardSaveDebounceRef.current);
    }
    cardSaveDebounceRef.current = setTimeout(() => {
      if (!excalidrawRef.current) return;
      const latestElements = excalidrawRef.current.getSceneElements();
      const latestAppState = excalidrawRef.current.getAppState();
      const latestFiles = excalidrawRef.current.getFiles();
      saveToServer(latestElements, latestAppState, latestFiles);
    }, 300);
  }, [saveToServer]);

  /**
   * Inserts a new rich text card with Notion-style editing at the center of the viewport.
   *
   * Creates two elements:
   * 1. An embeddable element with richtext:// link (displays the RichTextCard component)
   * 2. A hidden search text element (enables Excalidraw search to find card content)
   *
   * Both elements are grouped together and the card opens in edit mode immediately.
   * The search text element uses fontSize: 1 to minimize yellow highlight visibility.
   */
  const handleInsertRichTextCard = useCallback(() => {
    if (!excalidrawRef.current) return;

    const appState = excalidrawRef.current.getAppState();
    const scrollX = appState.scrollX || 0;
    const scrollY = appState.scrollY || 0;
    const zoom = appState.zoom?.value || 1;
    const viewportWidth = appState.width || 800;
    const viewportHeight = appState.height || 600;

    // Calculate center in scene coordinates
    const centerX = -scrollX + viewportWidth / 2 / zoom;
    const centerY = -scrollY + viewportHeight / 2 / zoom;

    const cardWidth = 400;
    const cardHeight = 300;
    const seed = Math.floor(Math.random() * 2000000000);
    const elementId = `rt-${Date.now()}-${Math.random()
      .toString(36)
      .slice(2, 9)}`;
    const searchTextId = `rtsearch-${elementId}`;
    const groupId = `rtgroup-${elementId}`;

    // Default rich text content (empty for a fresh start)
    const defaultRichTextContent = JSON.stringify({
      type: "doc",
      content: [
        {
          type: "heading",
          attrs: { level: 1 },
          content: [{ type: "text", text: "New Rich Text Card" }],
        },
        {
          type: "paragraph",
          content: [
            {
              type: "text",
              text: "Double-click to edit this card. Use the toolbar for formatting.",
            },
          ],
        },
      ],
    });

    const searchableText = "New Rich Text Card Double-click to edit this card.";

    // Create embeddable element for rich text card
    const richTextElement = {
      id: elementId,
      type: "embeddable" as const,
      x: centerX - cardWidth / 2,
      y: centerY - cardHeight / 2,
      width: cardWidth,
      height: cardHeight,
      angle: 0,
      strokeColor: "#1e1e1e",
      backgroundColor: "#ffffff",
      fillStyle: "solid" as const,
      strokeWidth: 1,
      strokeStyle: "solid" as const,
      roughness: 0,
      opacity: 100,
      groupIds: [groupId],
      frameId: null,
      index: null,
      roundness: { type: 3 },
      seed: seed,
      version: 1,
      versionNonce: seed,
      isDeleted: false,
      boundElements: null,
      updated: Date.now(),
      link: `richtext://${elementId}`,
      locked: false,
      customData: {
        richTextContent: defaultRichTextContent,
        isRichTextCard: true,
        searchTextElementId: searchTextId,
      },
    };

    // Create a hidden text element for search indexing
    // Positioned at same location as card for proper search navigation
    const searchTextElement = {
      id: searchTextId,
      type: "text" as const,
      x: centerX - cardWidth / 2, // Same position as card
      y: centerY - cardHeight / 2,
      width: cardWidth, // Match card width for proper zoom on search navigation
      height: cardHeight, // Match card height for proper zoom on search navigation
      angle: 0,
      strokeColor: "transparent",
      backgroundColor: "transparent",
      fillStyle: "solid" as const,
      strokeWidth: 0,
      strokeStyle: "solid" as const,
      roughness: 0,
      opacity: 0, // Invisible
      groupIds: [groupId],
      frameId: null,
      index: null,
      roundness: null,
      seed: seed + 1,
      version: 1,
      versionNonce: seed + 1,
      isDeleted: false,
      boundElements: null,
      updated: Date.now(),
      link: null,
      locked: true,
      text: searchableText,
      originalText: searchableText,
      fontSize: 1, // Normal font for proper zoom to minimize highlight box
      fontFamily: 1,
      textAlign: "left" as const,
      verticalAlign: "top" as const,
      containerId: null,
      lineHeight: 1.25,
      autoResize: false,
      customData: {
        isRichTextSearchText: true,
        parentRichTextCardId: elementId,
      },
    };

    const currentElements = excalidrawRef.current.getSceneElements();
    const newElements = [
      ...currentElements,
      richTextElement,
      searchTextElement,
    ];
    excalidrawRef.current.updateScene({
      elements: newElements,
    });

    hasUnsavedChangesRef.current = true;

    // Debounced save to prevent save storms when rapidly inserting cards
    // Uses 300ms debounce - fast enough to feel instant, slow enough to batch
    if (cardSaveDebounceRef.current) {
      clearTimeout(cardSaveDebounceRef.current);
    }
    cardSaveDebounceRef.current = setTimeout(() => {
      if (!excalidrawRef.current) return;
      const latestElements = excalidrawRef.current.getSceneElements();
      const latestAppState = excalidrawRef.current.getAppState();
      const latestFiles = excalidrawRef.current.getFiles();
      saveToServer(latestElements, latestAppState, latestFiles);
    }, 300);
  }, [saveToServer]);

  // Validate embeddable URLs - accept markdown:// and richtext:// schemes
  const validateEmbeddable = useCallback((url: string) => {
    if (url.startsWith("markdown://") || url.startsWith("richtext://")) {
      return true;
    }
    // Allow standard embeddables (YouTube, etc.)
    return undefined; // Let Excalidraw handle with default validation
  }, []);

  // Render custom embeddable content for markdown and rich text cards
  const renderEmbeddable = useCallback(
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (element: any, appState: ExcalidrawAppState) => {
      // Check if this is a markdown card
      if (
        element.link?.startsWith("markdown://") ||
        element.customData?.isMarkdownCard
      ) {
        return (
          <MarkdownCard
            element={element}
            appState={appState}
            onEdit={viewMode ? undefined : handleEditMarkdownCard}
          />
        );
      }
      // Check if this is a rich text card
      if (
        element.link?.startsWith("richtext://") ||
        element.customData?.isRichTextCard
      ) {
        return (
          <RichTextCard
            element={element}
            appState={appState}
            onEdit={viewMode ? undefined : handleEditRichTextCard}
          />
        );
      }
      // Return null for non-custom embeddables (use default rendering)
      return null;
    },
    [handleEditMarkdownCard, handleEditRichTextCard, viewMode]
  );

  // Warn before leaving with unsaved changes
  useEffect(() => {
    const handleBeforeUnload = (e: BeforeUnloadEvent) => {
      if (hasUnsavedChangesRef.current) {
        e.preventDefault();
        e.returnValue = "";
      }
    };

    window.addEventListener("beforeunload", handleBeforeUnload);
    return () => {
      window.removeEventListener("beforeunload", handleBeforeUnload);
      // Cleanup debounce timer on unmount
      if (cardSaveDebounceRef.current) {
        clearTimeout(cardSaveDebounceRef.current);
      }
      if (zoomCorrectionTimeoutRef.current) {
        clearTimeout(zoomCorrectionTimeoutRef.current);
      }
    };
  }, []);

  if (loadError) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-center">
          <p className="text-red-600 dark:text-red-400">{loadError}</p>
        </div>
      </div>
    );
  }

  if (!board || !initialData) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-600" />
      </div>
    );
  }

  return (
    <div className="relative h-full w-full">
      {/* Save indicator - only show when not in view mode */}
      {!viewMode && (
        <SaveIndicator
          status={saveStatus}
          lastSaved={lastSaved}
          onManualSave={handleManualSave}
          onShowHistory={() => setShowHistory(true)}
          storageSize={storageSize}
        />
      )}

      {/* Excalidraw */}
      <Excalidraw
        excalidrawAPI={(api) => {
          excalidrawRef.current = api as ExcalidrawAPI;

          // Poll for elements and run migration when they're loaded
          const checkForElements = () => {
            if (searchTextMigrationDoneRef.current) return;
            const elements = api.getSceneElements();
            if (elements.length > 0) {
              migrateSearchTextElements(api as ExcalidrawAPI);
            } else {
              // Try again in 200ms
              setTimeout(checkForElements, 200);
            }
          };
          setTimeout(checkForElements, 100);

          // Subscribe to changes to correct extreme zoom during search navigation
          api.onChange((elements, appState) => {
            // Also try migration from onChange as backup
            if (!searchTextMigrationDoneRef.current && elements.length > 0) {
              migrateSearchTextElements(api as ExcalidrawAPI);
            }

            const currentZoom = appState.zoom?.value || 1;
            const hasActiveSearch =
              appState.searchMatches && appState.searchMatches.length > 0;

            // Correct extreme zoom during search (Excalidraw sometimes zooms too much)
            if (hasActiveSearch && currentZoom > 2) {
              requestAnimationFrame(() => {
                if (excalidrawRef.current) {
                  const state = excalidrawRef.current.getAppState();
                  if ((state.zoom?.value || 1) > 1.5) {
                    excalidrawRef.current.updateScene({
                      appState: {
                        zoom: { value: 1 as 0.1 },
                      },
                    });
                  }
                }
              });
            }
          });
        }}
        initialData={{
          elements: initialData.elements,
          appState: {
            ...initialData.appState,
            collaborators,
            viewModeEnabled: viewMode,
          },
          files: initialData.files,
        }}
        viewModeEnabled={viewMode}
        onChange={viewMode ? undefined : handleChange}
        onPointerUpdate={handlePointerUpdate}
        validateEmbeddable={validateEmbeddable}
        renderEmbeddable={renderEmbeddable}
        UIOptions={{
          canvasActions: {
            loadScene: !viewMode,
            export: { saveFileToDisk: true },
            saveToActiveFile: false,
          },
        }}
      >
        {/* Custom Footer with tool buttons - centered */}
        <Footer>
          <div
            style={{
              position: "absolute",
              left: "50%",
              transform: "translateX(-50%)",
              bottom: 0,
              display: "flex",
              justifyContent: "center",
              pointerEvents: "none",
            }}
          >
            <div
              className="Island"
              style={{
                display: "flex",
                alignItems: "center",
                gap: "0.375rem",
                padding: "0.25rem",
                borderRadius: "0.5rem",
                backgroundColor: "var(--island-bg-color, #fff)",
                boxShadow: "var(--shadow-island, 0 1px 5px rgba(0,0,0,.15))",
                pointerEvents: "auto",
              }}
            >
              {/* View/Edit Mode Toggle */}
              {onViewModeChange && (
                <button
                  onClick={() => onViewModeChange(!viewMode)}
                  className="ToolIcon_type_button"
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    gap: "0.25rem",
                    padding: "0.5rem 0.75rem",
                    borderRadius: "0.5rem",
                    border: "none",
                    cursor: "pointer",
                    fontSize: "0.75rem",
                    fontWeight: 500,
                    backgroundColor: viewMode
                      ? "var(--color-primary, #6965db)"
                      : "transparent",
                    color: viewMode
                      ? "#fff"
                      : "var(--color-on-surface, #1b1b1f)",
                  }}
                  title={
                    viewMode
                      ? "Switch to Edit mode"
                      : "Switch to View-only mode"
                  }
                >
                  {viewMode ? (
                    <svg
                      width="16"
                      height="16"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"
                      />
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"
                      />
                    </svg>
                  ) : (
                    <svg
                      width="16"
                      height="16"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z"
                      />
                    </svg>
                  )}
                  {viewMode ? "View" : "Edit"}
                </button>
              )}

              {/* Separator */}
              {onViewModeChange && !viewMode && (
                <div
                  style={{
                    width: "1px",
                    height: "1.5rem",
                    backgroundColor: "var(--default-border-color, #e0e0e0)",
                  }}
                />
              )}

              {/* Markdown Button - only show in edit mode */}
              {!viewMode && (
                <button
                  onClick={handleInsertMarkdownCard}
                  className="ToolIcon_type_button"
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    gap: "0.25rem",
                    padding: "0.5rem 0.75rem",
                    borderRadius: "0.5rem",
                    border: "none",
                    cursor: "pointer",
                    fontSize: "0.75rem",
                    fontWeight: 500,
                    backgroundColor: "transparent",
                    color: "var(--color-on-surface, #1b1b1f)",
                  }}
                  title="Insert Markdown Card (supports mermaid.js diagrams)"
                >
                  <svg
                    width="16"
                    height="16"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
                    />
                  </svg>
                  Markdown
                </button>
              )}

              {/* Rich Text Button - only show in edit mode */}
              {!viewMode && (
                <button
                  onClick={handleInsertRichTextCard}
                  className="ToolIcon_type_button"
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    gap: "0.25rem",
                    padding: "0.5rem 0.75rem",
                    borderRadius: "0.5rem",
                    border: "none",
                    cursor: "pointer",
                    fontSize: "0.75rem",
                    fontWeight: 500,
                    backgroundColor: "transparent",
                    color: "var(--color-on-surface, #1b1b1f)",
                  }}
                  title="Insert Rich Text Card (Notion-style editor)"
                >
                  <svg
                    width="16"
                    height="16"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"
                    />
                  </svg>
                  Rich Text
                </button>
              )}
            </div>
          </div>
        </Footer>
      </Excalidraw>

      {/* Version History Sidebar */}
      {showHistory && (
        <VersionHistory
          boardId={boardId}
          onClose={() => setShowHistory(false)}
          onRestore={handleRestoreVersion}
        />
      )}

      {/* Markdown Card Editor Modal */}
      <MarkdownCardEditor
        isOpen={showMarkdownEditor}
        initialMarkdown={editingMarkdownContent}
        onSave={handleSaveMarkdownCard}
        onClose={() => {
          setShowMarkdownEditor(false);
          setEditingMarkdownElementId(null);
          setEditingMarkdownContent("");
        }}
      />

      {/* Rich Text Card Editor Modal */}
      <RichTextCardEditor
        isOpen={showRichTextEditor}
        initialContent={editingRichTextContent}
        onSave={handleSaveRichTextCard}
        onClose={() => {
          setShowRichTextEditor(false);
          setEditingRichTextElementId(null);
          setEditingRichTextContent("");
        }}
      />

      {/* Restore Version Confirmation Modal */}
      <Modal
        isOpen={showRestoreModal}
        onClose={() => setShowRestoreModal(false)}
        title="Restore Version"
        size="sm"
      >
        <div className="space-y-4">
          <p className="text-gray-600 dark:text-gray-400">
            Are you sure you want to restore{" "}
            <strong className="text-gray-900 dark:text-gray-100">
              version {versionToRestore?.version}
            </strong>
            ?
          </p>
          <p className="text-sm text-gray-500 dark:text-gray-500">
            This will replace your current board content with the selected
            version. A new version will be created with the restored content.
          </p>
          <div className="flex justify-end gap-2 pt-2">
            <Button
              variant="secondary"
              onClick={() => setShowRestoreModal(false)}
              disabled={restoring}
            >
              Cancel
            </Button>
            <Button
              variant="primary"
              onClick={confirmRestoreVersion}
              disabled={restoring}
            >
              {restoring ? "Restoring..." : "Restore Version"}
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
