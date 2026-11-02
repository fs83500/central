package server

import (
	"fmt"
	"log"
	"strings"
	"time"
)

// ensureTelemetryPartitions creates the monthly partitions for the current
// and the next month (idempotent — CREATE TABLE IF NOT EXISTS). Called on
// hub boot BEFORE any telemetry insert, and once a day by the maintenance
// loop. Migration 005 made `telemetry` PARTITION BY RANGE (ts); inserting
// into a month with no partition fails, so this MUST run first.
func (s *Server) EnsureTelemetryPartitions() error {
	now := time.Now().UTC()
	for _, m := range []time.Time{
		time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC),
		time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, 1, 0),
	} {
		name := fmt.Sprintf("telemetry_%s", m.Format("2006_01"))
		to := m.AddDate(0, 1, 0)
		// No bind parameters in CREATE TABLE ... PARTITION OF ... FOR VALUES
		// (pgx rejects them): inline ISO dates (controlled format, no injection).
		sql := fmt.Sprintf(
			`CREATE TABLE IF NOT EXISTS %s PARTITION OF telemetry
			 FOR VALUES FROM ('%s') TO ('%s')`,
			name, m.Format("2006-01-02"), to.Format("2006-01-02"))
		_, err := s.DB.Exec(sql)
		if err != nil {
			// Concurrent boot (docker-compose scale) can race: IF NOT EXISTS
			// is not atomic for partitions. A duplicate-object error here is
			// harmless — someone else created it first.
			if isAlreadyExists(err) {
				continue
			}
			return fmt.Errorf("partition %s: %w", name, err)
		}
		log.Printf("telemetry partition ready: %s", name)
	}
	return nil
}

// isAlreadyExists matches the PG "already exists" family (42P07 duplicate
// table, 42710 duplicate object).
func isAlreadyExists(err error) bool {
	return err != nil && strings.Contains(err.Error(), "already exists")
}

// retentionLoop detaches/drops partitions older than the retention (90 days
// = 3 months, SPEC: "rétention 90 j"). Runs every 24 h via ug_telemetry_retention().
func (s *Server) RetentionLoop(stop <-chan struct{}) {
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	// first pass right away at boot
	s.runRetention()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			s.runRetention()
		}
	}
}

func (s *Server) runRetention() {
	var dropped int
	if err := s.DB.QueryRow(`SELECT ug_telemetry_retention(3)`).Scan(&dropped); err != nil {
		log.Printf("telemetry retention: %v", err)
		return
	}
	if dropped > 0 {
		log.Printf("telemetry retention: dropped %d monthly partition(s)", dropped)
	}
}
