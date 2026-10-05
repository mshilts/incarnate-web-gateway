package httpapi

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"embed"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mshilts/incarnate-web-gateway/internal/config"
	"nhooyr.io/websocket"
)

//go:embed testdata/map-static/*.jsonl.gz
var mapStaticCaptures embed.FS

func TestPlayWSForwardsFullMapStaticFramesAndFollowingStatus(t *testing.T) {
	cases := []struct {
		name        string
		mapName     string
		widthCells  int
		heightCells int
		capture     string
	}{
		{
			name:        "maze",
			mapName:     "Sordon's Castle Maze Controler",
			widthCells:  208,
			heightCells: 164,
			capture:     "testdata/map-static/maze-map_static.jsonl.gz",
		},
		{
			name:        "dungeon",
			mapName:     "Sordon's Dungeon Controler",
			widthCells:  200,
			heightCells: 200,
			capture:     "testdata/map-static/dungeon-map_static.jsonl.gz",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mapFrame := readMapStaticCapture(t, tc.capture)
			if int64(len(mapFrame)) <= config.DefaultMaxFrameBytes {
				t.Fatalf("captured map frame size = %d, want more than the production limit %d", len(mapFrame), config.DefaultMaxFrameBytes)
			}
			var envelope struct {
				Type        string `json:"type"`
				MapName     string `json:"mapName"`
				WidthCells  int    `json:"widthCells"`
				HeightCells int    `json:"heightCells"`
			}
			if err := json.Unmarshal(mapFrame, &envelope); err != nil {
				t.Fatalf("unmarshal captured map: %v", err)
			}
			if envelope.Type != "map_static" || envelope.MapName != tc.mapName || envelope.WidthCells != tc.widthCells || envelope.HeightCells != tc.heightCells {
				t.Fatalf("captured map envelope = %+v", envelope)
			}

			cfg := testConfig()
			cfg.MaxFrameBytes = config.DefaultMaxFrameBytes
			server, err := NewServer(cfg, nil)
			if err != nil {
				t.Fatalf("NewServer: %v", err)
			}
			record, err := server.sessions.Create("matt", "Y3JlZA", "iphone")
			if err != nil {
				t.Fatalf("Create session: %v", err)
			}
			sessionBegin := make(chan map[string]any, 1)
			statusFrame := []byte(`{"type":"status","status":"ready"}`)
			server.java.Dialer = func(context.Context, string) (net.Conn, error) {
				javaSide, gatewaySide := net.Pipe()
				go func() {
					defer javaSide.Close()
					reader := bufio.NewReader(javaSide)
					line, err := reader.ReadBytes('\n')
					if err != nil {
						return
					}
					var req map[string]any
					_ = json.Unmarshal(line, &req)
					sessionBegin <- req
					if _, err := javaSide.Write([]byte(`{"type":"gateway_session_result","ok":true,"account":"matt","credentialLabel":"iphone"}` + "\n")); err != nil {
						return
					}
					if _, err := javaSide.Write(mapFrame); err != nil {
						return
					}
					if _, err := javaSide.Write([]byte{'\n'}); err != nil {
						return
					}
					if _, err := javaSide.Write(append(statusFrame, '\n')); err != nil {
						return
					}
					_, _ = io.Copy(io.Discard, javaSide)
				}()
				return gatewaySide, nil
			}
			httpServer := httptest.NewServer(server.Handler())
			defer httpServer.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			wsURL := "ws" + strings.TrimPrefix(httpServer.URL, "http") + "/play/ws"
			wsConn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
				HTTPHeader: http.Header{
					"Origin": []string{config.DefaultPublicOrigin},
					"Cookie": []string{(&http.Cookie{Name: config.DefaultSessionCookieName, Value: record.ID}).String()},
				},
			})
			if err != nil {
				t.Fatalf("Dial websocket: %v", err)
			}
			defer wsConn.Close(websocket.StatusNormalClosure, "")
			wsConn.SetReadLimit(int64(len(mapFrame) + len(statusFrame) + 1))

			select {
			case req := <-sessionBegin:
				if req["type"] != "gateway_session_begin" || req["account"] != "matt" || req["signature"] == "" {
					t.Fatalf("bad session begin: %+v", req)
				}
			case <-ctx.Done():
				t.Fatal("timed out waiting for Java session begin")
			}

			messageType, data, err := wsConn.Read(ctx)
			if err != nil {
				t.Fatalf("read full %s map_static frame (%d bytes): %v", tc.name, len(mapFrame), err)
			}
			if messageType != websocket.MessageText || !bytes.Equal(data, mapFrame) {
				t.Fatalf("unexpected map frame: type=%v bytes=%d, want text frame with %d bytes", messageType, len(data), len(mapFrame))
			}

			messageType, data, err = wsConn.Read(ctx)
			if err != nil {
				t.Fatalf("read following status frame: %v", err)
			}
			if messageType != websocket.MessageText || !bytes.Equal(data, statusFrame) {
				t.Fatalf("following frame = type %v, %s, want text %s", messageType, data, statusFrame)
			}
		})
	}
}

func TestPlayWSRejectsBrowserFramesAboveConfiguredLimit(t *testing.T) {
	cfg := testConfig()
	cfg.MaxFrameBytes = 1024
	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	record, err := server.sessions.Create("matt", "Y3JlZA", "iphone")
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}
	sessionBegin := make(chan map[string]any, 1)
	forwarded := make(chan []byte, 1)
	server.java.Dialer = func(context.Context, string) (net.Conn, error) {
		javaSide, gatewaySide := net.Pipe()
		go func() {
			defer javaSide.Close()
			reader := bufio.NewReader(javaSide)
			line, err := reader.ReadBytes('\n')
			if err != nil {
				return
			}
			var req map[string]any
			_ = json.Unmarshal(line, &req)
			sessionBegin <- req
			if _, err := javaSide.Write([]byte(`{"type":"gateway_session_result","ok":true,"account":"matt","credentialLabel":"iphone"}` + "\n")); err != nil {
				return
			}
			line, _ = reader.ReadBytes('\n')
			forwarded <- line
		}()
		return gatewaySide, nil
	}
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	wsURL := "ws" + strings.TrimPrefix(httpServer.URL, "http") + "/play/ws"
	wsConn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader: http.Header{
			"Origin": []string{config.DefaultPublicOrigin},
			"Cookie": []string{(&http.Cookie{Name: config.DefaultSessionCookieName, Value: record.ID}).String()},
		},
	})
	if err != nil {
		t.Fatalf("Dial websocket: %v", err)
	}
	defer wsConn.Close(websocket.StatusNormalClosure, "")
	select {
	case req := <-sessionBegin:
		if req["type"] != "gateway_session_begin" || req["account"] != "matt" || req["signature"] == "" {
			t.Fatalf("bad session begin: %+v", req)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for Java session begin")
	}

	frame := []byte(`{"type":"ping","padding":"` + strings.Repeat("x", int(cfg.MaxFrameBytes)) + `"}`)
	if int64(len(frame)) <= cfg.MaxFrameBytes {
		t.Fatalf("test frame size = %d, want more than configured limit %d", len(frame), cfg.MaxFrameBytes)
	}
	if err := wsConn.Write(ctx, websocket.MessageText, frame); err != nil {
		t.Fatalf("write oversized browser frame: %v", err)
	}
	if _, _, err := wsConn.Read(ctx); err == nil {
		t.Fatal("websocket remained open after oversized browser frame")
	}
	select {
	case line := <-forwarded:
		if len(line) != 0 {
			t.Fatalf("oversized browser frame reached Java: %d bytes", len(line))
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for Java connection to close")
	}
}

func readMapStaticCapture(t *testing.T, path string) []byte {
	t.Helper()
	compressed, err := mapStaticCaptures.ReadFile(path)
	if err != nil {
		t.Fatalf("read map_static capture: %v", err)
	}
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatalf("open compressed map_static capture: %v", err)
	}
	defer reader.Close()
	frame, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("decompress map_static capture: %v", err)
	}
	frame = bytes.TrimSuffix(frame, []byte{'\n'})
	if !json.Valid(frame) {
		t.Fatal("map_static capture is not valid JSON")
	}
	return frame
}
