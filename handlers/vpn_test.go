package handlers

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

type fakeXDPStatsReader struct {
	total       uint64
	dropped     uint64
	detailedErr error
	basicErr    error
}

type fakeTCStatsReader struct {
	stats map[uint32]uint64
	err   error
}

func (f *fakeXDPStatsReader) GetDetailedStats() (uint64, uint64, error) {
	if f.detailedErr != nil {
		return 0, 0, f.detailedErr
	}
	return f.total, f.dropped, nil
}

func (f *fakeXDPStatsReader) GetStats() (uint64, error) {
	if f.basicErr != nil {
		return 0, f.basicErr
	}
	return f.total, nil
}

func (f *fakeTCStatsReader) GetNATStats() (map[uint32]uint64, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.stats, nil
}

func TestCollectEBPFStatsReturnsOnlyRealFields(t *testing.T) {
	stats := collectEBPFStats(&fakeXDPStatsReader{
		total:   128,
		dropped: 7,
	})

	if !stats.EBPFEnabled {
		t.Fatalf("expected eBPF to be enabled")
	}
	if stats.TotalPackets != 128 {
		t.Fatalf("expected total packets 128, got %d", stats.TotalPackets)
	}
	if stats.DroppedPackets != 7 {
		t.Fatalf("expected dropped packets 7, got %d", stats.DroppedPackets)
	}

	payload, err := json.Marshal(stats)
	if err != nil {
		t.Fatalf("marshal stats: %v", err)
	}

	jsonString := string(payload)
	for _, field := range []string{"total_bytes", "dropped_bytes", "avg_packet_size", "filter_hits"} {
		if strings.Contains(jsonString, field) {
			t.Fatalf("unexpected estimated field %q in payload: %s", field, jsonString)
		}
	}
}

func TestCollectEBPFStatsFallsBackToBasicCounters(t *testing.T) {
	stats := collectEBPFStats(&fakeXDPStatsReader{
		total:       42,
		detailedErr: errors.New("detailed stats unavailable"),
	})

	if !stats.EBPFEnabled {
		t.Fatalf("expected eBPF to be enabled")
	}
	if stats.TotalPackets != 42 {
		t.Fatalf("expected total packets 42, got %d", stats.TotalPackets)
	}
	if stats.DroppedPackets != 0 {
		t.Fatalf("expected dropped packets 0 when falling back, got %d", stats.DroppedPackets)
	}
}

func TestGetEBPFStatsHandlerReturnsOnlyRealFields(t *testing.T) {
	gin.SetMode(gin.TestMode)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	handler := &VPNHandler{
		statsReaderOverride: &fakeXDPStatsReader{
			total:   128,
			dropped: 7,
		},
		tcStatsReaderOverride: &fakeTCStatsReader{
			stats: map[uint32]uint64{
				0: 15,
				4: 80,
				5: 2,
			},
		},
	}

	handler.GetEBPFStats(ctx)

	body := recorder.Body.String()
	for _, field := range []string{
		"\"ebpf_enabled\":true",
		"\"total_packets\":128",
		"\"dropped_packets\":7",
		"\"tc_nat_performed_packets\":15",
		"\"tc_total_packets\":80",
		"\"tc_vpn_network_not_configured_packets\":2",
	} {
		if !strings.Contains(body, field) {
			t.Fatalf("expected response to contain %s, got %s", field, body)
		}
	}
	for _, field := range []string{"total_bytes", "dropped_bytes", "avg_packet_size", "filter_hits", "timestamp"} {
		if strings.Contains(body, field) {
			t.Fatalf("unexpected field %q in response: %s", field, body)
		}
	}
}

func TestWriteEBPFStatsEventIncludesTimestampAndRealFields(t *testing.T) {
	gin.SetMode(gin.TestMode)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	handler := &VPNHandler{
		statsReaderOverride: &fakeXDPStatsReader{
			total:       42,
			detailedErr: errors.New("detailed stats unavailable"),
		},
		tcStatsReaderOverride: &fakeTCStatsReader{
			stats: map[uint32]uint64{
				0: 9,
				4: 30,
				5: 1,
			},
		},
	}

	handler.writeEBPFStatsEvent(ctx, 1710000000)

	body := recorder.Body.String()
	for _, field := range []string{
		"event:stats",
		"\"ebpf_enabled\":true",
		"\"total_packets\":42",
		"\"dropped_packets\":0",
		"\"tc_nat_performed_packets\":9",
		"\"tc_total_packets\":30",
		"\"tc_vpn_network_not_configured_packets\":1",
		"\"timestamp\":1710000000",
	} {
		if !strings.Contains(body, field) {
			t.Fatalf("expected SSE payload to contain %s, got %s", field, body)
		}
	}
	for _, field := range []string{"total_bytes", "dropped_bytes", "avg_packet_size", "filter_hits"} {
		if strings.Contains(body, field) {
			t.Fatalf("unexpected estimated field %q in SSE payload: %s", field, body)
		}
	}
}
