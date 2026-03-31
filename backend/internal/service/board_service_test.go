package service

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestExtractSearchableContent_TextElements(t *testing.T) {
	scene := `{"elements":[{"type":"text","text":"Hello World"},{"type":"text","text":"Search me"}]}`
	result := extractSearchableContent(json.RawMessage(scene))
	if result != "Hello World Search me" {
		t.Errorf("expected 'Hello World Search me', got '%s'", result)
	}
}

func TestExtractSearchableContent_SkipsDeleted(t *testing.T) {
	scene := `{"elements":[{"type":"text","text":"visible"},{"type":"text","text":"deleted","isDeleted":true}]}`
	result := extractSearchableContent(json.RawMessage(scene))
	if result != "visible" {
		t.Errorf("expected 'visible', got '%s'", result)
	}
}

func TestExtractSearchableContent_SkipsSearchTextElements(t *testing.T) {
	scene := `{"elements":[{"type":"text","text":"real text"},{"type":"text","text":"search duplicate","customData":{"isMarkdownSearchText":true}}]}`
	result := extractSearchableContent(json.RawMessage(scene))
	if result != "real text" {
		t.Errorf("expected 'real text', got '%s'", result)
	}
}

func TestExtractSearchableContent_MarkdownCards(t *testing.T) {
	scene := `{"elements":[{"type":"rectangle","customData":{"isMarkdownCard":true,"markdown":"# Hello\n**bold** text"}}]}`
	result := extractSearchableContent(json.RawMessage(scene))
	if !strings.Contains(result, "Hello") || !strings.Contains(result, "bold text") {
		t.Errorf("expected markdown stripped text, got '%s'", result)
	}
}

func TestExtractSearchableContent_RichTextCards(t *testing.T) {
	tiptap := `{"type":"doc","content":[{"type":"paragraph","content":[{"type":"text","text":"rich content"}]}]}`
	escaped := strings.ReplaceAll(tiptap, `"`, `\"`)
	scene := `{"elements":[{"type":"rectangle","customData":{"isRichTextCard":true,"richTextContent":"` + escaped + `"}}]}`
	result := extractSearchableContent(json.RawMessage(scene))
	if !strings.Contains(result, "rich content") {
		t.Errorf("expected 'rich content', got '%s'", result)
	}
}

func TestExtractSearchableContent_EmptyScene(t *testing.T) {
	result := extractSearchableContent(nil)
	if result != "" {
		t.Errorf("expected empty, got '%s'", result)
	}
}

func TestExtractSearchableContent_Truncation(t *testing.T) {
	longText := strings.Repeat("a", 60000)
	scene := `{"elements":[{"type":"text","text":"` + longText + `"}]}`
	result := extractSearchableContent(json.RawMessage(scene))
	if len(result) > maxSearchContentLength {
		t.Errorf("expected max %d chars, got %d", maxSearchContentLength, len(result))
	}
}

func TestStripMarkdownToPlainText(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"headers", "# Title\n## Subtitle", "Title\nSubtitle"},
		{"bold and italic", "**bold** and *italic*", "bold and italic"},
		{"links", "[click here](https://example.com)", "click here"},
		{"images", "![alt text](image.png)", "alt text"},
		{"code blocks", "before\n```\ncode\n```\nafter", "before\n\nafter"},
		{"inline code", "use `fmt.Println` here", "use  here"},
		{"list markers", "- item one\n- item two\n1. numbered", "item one\nitem two\nnumbered"},
		{"blockquotes", "> quoted text", "quoted text"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripMarkdownToPlainText(tt.input)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractTextFromTiptapJSON(t *testing.T) {
	node := tiptapNode{
		Type: "doc",
		Content: []tiptapNode{
			{Type: "paragraph", Content: []tiptapNode{{Text: "Hello"}, {Text: " world"}}},
			{Type: "paragraph", Content: []tiptapNode{{Text: "Second paragraph"}}},
		},
	}
	result := extractTextFromTiptapJSON(node)
	if !strings.Contains(result, "Hello") || !strings.Contains(result, "world") || !strings.Contains(result, "Second paragraph") {
		t.Errorf("expected tiptap text extraction, got '%s'", result)
	}
}

func TestCleanOrphanedFiles(t *testing.T) {
	scene := `{"elements":[{"type":"image","fileId":"used1","x":10,"y":20,"width":100,"height":50},{"type":"text","text":"hello","x":5,"y":5,"strokeColor":"#000"},{"type":"image","fileId":"used2"},{"type":"arrow","points":[[0,0],[100,200]],"x":30}],"files":{"used1":{"data":"a"},"used2":{"data":"b"},"orphan1":{"data":"c"}}}`
	result := cleanOrphanedFiles(json.RawMessage(scene))

	var parsed struct {
		Elements []map[string]interface{} `json:"elements"`
		Files    map[string]interface{}   `json:"files"`
	}
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if len(parsed.Files) != 2 {
		t.Errorf("expected 2 files, got %d", len(parsed.Files))
	}
	if _, ok := parsed.Files["orphan1"]; ok {
		t.Error("orphan1 should have been removed")
	}
	// Verify all element properties are preserved (not stripped by marshaling)
	if len(parsed.Elements) != 4 {
		t.Fatalf("expected 4 elements, got %d", len(parsed.Elements))
	}
	img := parsed.Elements[0]
	if img["x"] != float64(10) || img["y"] != float64(20) || img["width"] != float64(100) {
		t.Errorf("image element properties lost: %v", img)
	}
	txt := parsed.Elements[1]
	if txt["strokeColor"] != "#000" {
		t.Errorf("text element properties lost: %v", txt)
	}
	arrow := parsed.Elements[3]
	if arrow["points"] == nil || arrow["x"] != float64(30) {
		t.Errorf("arrow element properties lost: %v", arrow)
	}
}

func TestCleanOrphanedFiles_NoFiles(t *testing.T) {
	scene := `{"elements":[{"type":"text","text":"hi"}]}`
	result := cleanOrphanedFiles(json.RawMessage(scene))
	if string(result) != scene {
		t.Errorf("expected unchanged scene")
	}
}

func TestCleanOrphanedFiles_AllUsed(t *testing.T) {
	scene := `{"elements":[{"type":"image","fileId":"f1"}],"files":{"f1":{"data":"x"}}}`
	result := cleanOrphanedFiles(json.RawMessage(scene))
	if string(result) != scene {
		t.Errorf("expected unchanged scene when all files used")
	}
}

func TestGenerateEtag(t *testing.T) {
	etag1 := generateEtag("board1")
	etag2 := generateEtag("board1")
	if etag1 == etag2 {
		t.Error("etags should be unique")
	}
	if !strings.HasPrefix(etag1, "board1-") {
		t.Errorf("etag should start with prefix, got '%s'", etag1)
	}
}

func TestCompactSceneForStorage_StripsDeletedElements(t *testing.T) {
	scene := `{"elements":[{"type":"text","text":"keep","isDeleted":false},{"type":"text","text":"remove","isDeleted":true},{"type":"rect","width":100}]}`
	result := compactSceneForStorage(json.RawMessage(scene))

	var parsed struct {
		Elements []map[string]interface{} `json:"elements"`
	}
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if len(parsed.Elements) != 2 {
		t.Errorf("expected 2 elements after stripping deleted, got %d", len(parsed.Elements))
	}
	for _, el := range parsed.Elements {
		if el["text"] == "remove" {
			t.Error("deleted element should have been stripped")
		}
	}
}

func TestCompactSceneForStorage_StripsFileDataURL(t *testing.T) {
	// dataURL should be PRESERVED (frontend needs it to render images)
	scene := `{"elements":[{"type":"image","fileId":"f1"}],"files":{"f1":{"id":"f1","mimeType":"image/png","dataURL":"data:image/png;base64,AAAA..."}}}`
	result := compactSceneForStorage(json.RawMessage(scene))

	var parsed struct {
		Files map[string]map[string]interface{} `json:"files"`
	}
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	f1 := parsed.Files["f1"]
	if _, hasData := f1["dataURL"]; !hasData {
		t.Error("dataURL should be preserved for frontend rendering")
	}
	if f1["id"] != "f1" {
		t.Error("file id should be preserved")
	}
	if f1["mimeType"] != "image/png" {
		t.Error("file mimeType should be preserved")
	}
}

func TestCompactSceneForStorage_NoChanges(t *testing.T) {
	scene := `{"elements":[{"type":"text","text":"hi"}]}`
	result := compactSceneForStorage(json.RawMessage(scene))
	if string(result) != scene {
		t.Errorf("expected unchanged scene when no deleted elements or file data")
	}
}

func TestCompactSceneForStorage_EmptyInput(t *testing.T) {
	result := compactSceneForStorage(nil)
	if result != nil {
		t.Error("expected nil for nil input")
	}
	result = compactSceneForStorage(json.RawMessage{})
	if len(result) != 0 {
		t.Error("expected empty for empty input")
	}
}

func TestCompactSceneForStorage_BothDeletedAndDataURL(t *testing.T) {
	scene := `{"elements":[{"type":"image","fileId":"f1","isDeleted":false},{"type":"rect","isDeleted":true}],"files":{"f1":{"id":"f1","dataURL":"data:base64..."}}}`
	result := compactSceneForStorage(json.RawMessage(scene))

	var parsed struct {
		Elements []map[string]interface{}          `json:"elements"`
		Files    map[string]map[string]interface{} `json:"files"`
	}
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if len(parsed.Elements) != 1 {
		t.Errorf("expected 1 element (deleted stripped), got %d", len(parsed.Elements))
	}
	if _, hasData := parsed.Files["f1"]["dataURL"]; !hasData {
		t.Error("dataURL should be preserved for frontend rendering")
	}
}
