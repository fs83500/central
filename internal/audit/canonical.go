package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// canonicalJSON mirrors jsonb_build_object output exactly as the PostgreSQL
// trigger builds it (migrations/hub/001_skeleton.sql). Two subtleties of PG
// jsonb serialization are reproduced here:
//
//  1. Key order: jsonb sorts keys by (length, then bytewise) — NOT plain
//     lexicographic ("ts" (2) < "seq" (3) < "actor"/"action" (6)...).
//  2. Spacing: jsonb output has a space after ':' but none after ','.
//
// The Go verifier recomputes hashes with this form so anyone with a raw
// database dump can verify the chain without PostgreSQL.
func canonicalJSON(ev Event, tsFormat string) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString(`{"ts": `)
	writeJSONString(&b, ev.TS.UTC().Format(tsFormat))
	b.WriteString(`, "seq": `)
	fmt.Fprintf(&b, `%d`, ev.Seq)
	b.WriteString(`, "actor": `)
	writeJSONString(&b, ev.Actor)
	b.WriteString(`, "action": `)
	writeJSONString(&b, ev.Action)
	b.WriteString(`, "params": `)
	pb, err := paramsJSONB(ev.Params)
	if err != nil {
		return nil, err
	}
	b.Write(pb)
	b.WriteString(`, "result": `)
	writeJSONString(&b, ev.Result)
	b.WriteString(`, "target_id": `)
	writeJSONString(&b, ev.TargetID)
	b.WriteString(`, "actor_type": `)
	writeJSONString(&b, ev.ActorType)
	b.WriteString(`, "target_type": `)
	writeJSONString(&b, ev.TargetType)
	b.WriteString(`}`)
	return b.Bytes(), nil
}

// paramsJSONB serializes params like a PG jsonb value: {} when empty,
// otherwise the compact form sorted by (length, bytewise) keys.
func paramsJSONB(raw json.RawMessage) ([]byte, error) {
	if len(raw) == 0 {
		return []byte("{}"), nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	if len(m) == 0 {
		return []byte("{}"), nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	jsonbKeySort(keys)
	var b strings.Builder
	b.WriteString("{")
	for i, k := range keys {
		if i > 0 {
			b.WriteString(", ")
		}
		v, err := json.Marshal(m[k])
		if err != nil {
			return nil, err
		}
		kb, _ := json.Marshal(k)
		b.Write(kb)
		b.WriteString(": ")
		b.Write(v)
	}
	b.WriteString("}")
	return []byte(b.String()), nil
}

// jsonbKeySort sorts keys the way PostgreSQL jsonb does: by key byte-length
// first, then bytewise comparison.
func jsonbKeySort(keys []string) {
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0; j-- {
			a, b := keys[j-1], keys[j]
			if len(a) < len(b) || (len(a) == len(b) && a < b) {
				break
			}
			keys[j-1], keys[j] = b, a
		}
	}
}

func writeJSONString(buf *bytes.Buffer, s string) {
	b, _ := json.Marshal(s)
	buf.Write(b)
}

// pgTimestampFormat is the to_char pattern used by the trigger:
// YYYY-MM-DDTHH24:MI:SS.USZ with fixed 6-digit microseconds.
const pgTimestampFormat = "2006-01-02T15:04:05.000000Z"

// HashCanonicalPG computes the hash exactly like the trigger:
// sha256(prev || canonical_jsonb). Exported so the hub's /audit/verify
// endpoint can double-check the DB-side chain with an independent
// implementation (defense in depth: two verifiers, one in SQL, one in Go).
func HashCanonicalPG(prev string, ev Event) (string, error) {
	canonical, err := canonicalJSON(ev, pgTimestampFormat)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte(prev), canonical...))
	return hex.EncodeToString(sum[:]), nil
}

// CanonicalDebug exposes the canonical form for tests/debugging.
func CanonicalDebug(ev Event) ([]byte, error) {
	return canonicalJSON(ev, pgTimestampFormat)
}
