package realtime

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// Room represents a board-scoped group of connected clients.
// It manages presence, message routing, cursor batching, and heartbeats.
type Room struct {
	boardID string
	clients map[*Client]struct{}
	mu      sync.RWMutex
	log     zerolog.Logger

	// Cursor batching — collects cursor updates and flushes at interval
	cursorBuf      map[string]*CursorPayload // userID → latest cursor
	cursorMu       sync.Mutex
	cursorInterval time.Duration

	maxConns   int
	colorIndex int
	onEmpty    func(boardID string) // callback when room becomes empty
	hub        *Hub                 // parent hub for message metrics
}

// RoomConfig holds configuration for a Room.
type RoomConfig struct {
	MaxConns       int
	CursorInterval time.Duration
	OnEmpty        func(boardID string)
	Hub            *Hub
}

// NewRoom creates a new Room for a board.
func NewRoom(boardID string, cfg RoomConfig, log zerolog.Logger) *Room {
	r := &Room{
		boardID:        boardID,
		clients:        make(map[*Client]struct{}),
		cursorBuf:      make(map[string]*CursorPayload),
		cursorInterval: cfg.CursorInterval,
		maxConns:       cfg.MaxConns,
		onEmpty:        cfg.OnEmpty,
		hub:            cfg.Hub,
		log:            log.With().Str("room", boardID).Logger(),
	}
	return r
}

// BoardID returns the board ID this room serves.
func (r *Room) BoardID() string {
	return r.boardID
}

// ClientCount returns the number of connected clients.
func (r *Room) ClientCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.clients)
}

// IsFull returns true if the room has reached its max connections.
func (r *Room) IsFull() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.maxConns > 0 && len(r.clients) >= r.maxConns
}

// Join adds a client to the room and broadcasts their arrival.
func (r *Room) Join(c *Client) {
	r.mu.Lock()
	r.clients[c] = struct{}{}
	count := len(r.clients)
	r.mu.Unlock()

	r.log.Info().Str("userId", c.info.UserID).Int("count", count).Msg("client joined")

	// Send the new client their own identity (needed for self-cursor filtering)
	welcome, _ := NewMessage(MsgTypeWelcome, "", WelcomePayload{Viewer: c.info})
	data, _ := json.Marshal(welcome)
	c.Send(data)

	// Notify others about the new viewer
	joined, _ := NewMessage(MsgTypeJoined, "", JoinedPayload{Viewer: c.info})
	r.broadcastExcept(c, joined)

	// Send current presence to the new client
	r.sendPresence(c)
}

// Leave removes a client from the room and broadcasts their departure.
func (r *Room) Leave(c *Client) {
	r.mu.Lock()
	_, exists := r.clients[c]
	if !exists {
		r.mu.Unlock()
		return
	}
	delete(r.clients, c)
	count := len(r.clients)
	r.mu.Unlock()

	r.log.Info().Str("userId", c.info.UserID).Int("count", count).Msg("client left")

	// Remove cursor
	r.cursorMu.Lock()
	delete(r.cursorBuf, c.info.UserID)
	r.cursorMu.Unlock()

	left, _ := NewMessage(MsgTypeLeft, "", LeftPayload{UserID: c.info.UserID})
	r.Broadcast(left)

	if count == 0 && r.onEmpty != nil {
		r.onEmpty(r.boardID)
	}
}

// HandleMessage processes an inbound message from a client.
func (r *Room) HandleMessage(sender *Client, msg *Message) {
	if r.hub != nil {
		r.hub.IncrMsgIn()
	}
	switch msg.Type {
	case MsgTypePing:
		pong, _ := NewMessage(MsgTypePong, "", nil)
		data, _ := json.Marshal(pong)
		sender.Send(data)

	case MsgTypeCursorMove:
		var cursor CursorPayload
		if err := json.Unmarshal(msg.Payload, &cursor); err != nil {
			return
		}
		cursor.UserID = sender.info.UserID
		cursor.Name = sender.info.Name
		cursor.Color = sender.info.Color

		r.cursorMu.Lock()
		r.cursorBuf[sender.info.UserID] = &cursor
		r.cursorMu.Unlock()

	case MsgTypeSceneUpdate:
		// Only allow users with write permissions to broadcast scene updates.
		// Viewers (from share links) should not be able to modify the board.
		if sender.info.Role == "VIEWER" || sender.info.Role == "viewer" {
			errMsg, _ := NewMessage(MsgTypeError, "", ErrorPayload{
				Code:    "FORBIDDEN",
				Message: "Viewers cannot modify the board",
			})
			data, _ := json.Marshal(errMsg)
			sender.Send(data)
			return
		}
		// Broadcast scene updates to all other clients (real-time sync)
		synced, _ := NewMessage(MsgTypeSceneSynced, sender.info.UserID, msg.Payload)
		r.broadcastExcept(sender, synced)

	default:
		r.log.Debug().Str("type", string(msg.Type)).Msg("unknown message type")
	}
}

// Broadcast sends a message to all connected clients.
func (r *Room) Broadcast(msg *Message) {
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}

	r.mu.RLock()
	n := len(r.clients)
	for c := range r.clients {
		c.Send(data)
	}
	r.mu.RUnlock()

	if r.hub != nil && n > 0 {
		r.hub.IncrMsgOut(int64(n))
	}
}

// broadcastExcept sends a message to all clients except the sender.
func (r *Room) broadcastExcept(sender *Client, msg *Message) {
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}

	r.mu.RLock()
	n := 0
	for c := range r.clients {
		if c != sender {
			c.Send(data)
			n++
		}
	}
	r.mu.RUnlock()

	if r.hub != nil && n > 0 {
		r.hub.IncrMsgOut(int64(n))
	}
}

// sendPresence sends the current viewer list to a specific client.
func (r *Room) sendPresence(target *Client) {
	r.mu.RLock()
	viewers := make([]ViewerInfo, 0, len(r.clients))
	for c := range r.clients {
		viewers = append(viewers, c.info)
	}
	r.mu.RUnlock()

	msg, _ := NewMessage(MsgTypePresence, "", PresencePayload{
		Viewers: viewers,
		Count:   len(viewers),
	})
	data, _ := json.Marshal(msg)
	target.Send(data)
}

// FlushCursors collects all buffered cursor updates and broadcasts them.
// Called periodically by the hub's cursor ticker.
func (r *Room) FlushCursors() {
	r.cursorMu.Lock()
	if len(r.cursorBuf) == 0 {
		r.cursorMu.Unlock()
		return
	}

	// Snapshot and clear
	cursors := make([]CursorPayload, 0, len(r.cursorBuf))
	for _, c := range r.cursorBuf {
		cursors = append(cursors, *c)
	}
	r.cursorBuf = make(map[string]*CursorPayload)
	r.cursorMu.Unlock()

	msg, _ := NewMessage(MsgTypeCursorUpdate, "", cursors)
	r.Broadcast(msg)
}

// NextColor assigns the next color in the palette.
func (r *Room) NextColor() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	color := AssignColor(r.colorIndex)
	r.colorIndex++
	return color
}
