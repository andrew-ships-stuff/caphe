package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/andrew-ships-stuff/caphe/internal/findings"
	_ "modernc.org/sqlite"
)

const SchemaVersion = 1

type Store struct{ db *sql.DB }

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	s := &Store{db: db}
	if err := s.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}
func (s *Store) Close() error { return s.db.Close() }
func (s *Store) migrate(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS executions(id TEXT PRIMARY KEY, workflow_digest TEXT NOT NULL, target TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT, status TEXT NOT NULL, manifest_json BLOB)`,
		`CREATE TABLE IF NOT EXISTS task_runs(execution_id TEXT NOT NULL, task_id TEXT NOT NULL, status TEXT NOT NULL, attempts INTEGER NOT NULL, artifact_digest TEXT, error_class TEXT, error_message TEXT, duration_ms INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(execution_id,task_id), FOREIGN KEY(execution_id) REFERENCES executions(id))`,
		`CREATE TABLE IF NOT EXISTS findings(id TEXT NOT NULL, execution_id TEXT NOT NULL, tool TEXT NOT NULL, rule_id TEXT NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL, finding_json BLOB NOT NULL, observed_at TEXT NOT NULL, PRIMARY KEY(id,execution_id), FOREIGN KEY(execution_id) REFERENCES executions(id))`,
		`CREATE TABLE IF NOT EXISTS graph_nodes(id TEXT PRIMARY KEY, type TEXT NOT NULL, status TEXT NOT NULL, source TEXT NOT NULL, artifact_digest TEXT, data_json BLOB NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS graph_edges(id TEXT PRIMARY KEY, source_id TEXT NOT NULL, target_id TEXT NOT NULL, type TEXT NOT NULL, status TEXT NOT NULL, provenance_json BLOB NOT NULL, FOREIGN KEY(source_id) REFERENCES graph_nodes(id), FOREIGN KEY(target_id) REFERENCES graph_nodes(id))`,
		`CREATE TABLE IF NOT EXISTS ai_cache(cache_key TEXT PRIMARY KEY, response_json BLOB NOT NULL, model_digest TEXT NOT NULL, prompt_version TEXT NOT NULL, schema_version TEXT NOT NULL, created_at TEXT NOT NULL)`,
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range statements {
		if _, err := tx.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(?,?)`, SchemaVersion, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) BeginExecution(ctx context.Context, id, digest, target string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO executions(id,workflow_digest,target,started_at,status) VALUES(?,?,?,?,?)`, id, digest, target, time.Now().UTC().Format(time.RFC3339Nano), "running")
	return err
}
func (s *Store) SaveTask(ctx context.Context, executionID, taskID, status string, attempts int, digest, errorClass, errorMessage string, duration time.Duration) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO task_runs(execution_id,task_id,status,attempts,artifact_digest,error_class,error_message,duration_ms) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(execution_id,task_id) DO UPDATE SET status=excluded.status,attempts=excluded.attempts,artifact_digest=excluded.artifact_digest,error_class=excluded.error_class,error_message=excluded.error_message,duration_ms=excluded.duration_ms`, executionID, taskID, status, attempts, digest, errorClass, errorMessage, duration.Milliseconds())
	return err
}
func (s *Store) FinishExecution(ctx context.Context, id, status string, manifest any) error {
	b, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE executions SET finished_at=?,status=?,manifest_json=? WHERE id=?`, time.Now().UTC().Format(time.RFC3339Nano), status, b, id)
	return err
}
func (s *Store) SaveFindings(ctx context.Context, executionID string, items []findings.Finding) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	for i := range items {
		f := items[i]
		f.ObservedAt = now
		b, err := json.Marshal(f)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO findings(id,execution_id,tool,rule_id,severity,title,finding_json,observed_at) VALUES(?,?,?,?,?,?,?,?)`, f.ID, executionID, f.Tool, f.RuleID, f.Severity, f.Title, b, now.Format(time.RFC3339Nano)); err != nil {
			return err
		}
		node := map[string]any{"finding": f}
		nb, _ := json.Marshal(node)
		if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO graph_nodes(id,type,status,source,artifact_digest,data_json) VALUES(?,?,?,?,?,?)`, f.ID, "Finding", "confirmed", f.Tool, f.ArtifactDigest, nb); err != nil {
			return err
		}
		if f.Location.Path != "" {
			sum := sha256.Sum256([]byte(f.Location.Path))
			fileID := "file:sha256:" + hex.EncodeToString(sum[:])
			fileData, _ := json.Marshal(map[string]any{"path": f.Location.Path})
			if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO graph_nodes(id,type,status,source,artifact_digest,data_json) VALUES(?,?,?,?,?,?)`, fileID, "SourceFile", "confirmed", "caphe.location", f.ArtifactDigest, fileData); err != nil {
				return err
			}
			edgeSum := sha256.Sum256([]byte(f.ID + "\x00REFERENCES\x00" + fileID))
			edgeID := "edge:sha256:" + hex.EncodeToString(edgeSum[:])
			prov, _ := json.Marshal(map[string]any{"method": "exact_scanner_location", "findingId": f.ID, "artifactDigest": f.ArtifactDigest})
			if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO graph_edges(id,source_id,target_id,type,status,provenance_json) VALUES(?,?,?,?,?,?)`, edgeID, f.ID, fileID, "REFERENCES", "confirmed", prov); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}
func (s *Store) ListFindings(ctx context.Context) ([]findings.Finding, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT finding_json FROM findings WHERE execution_id=(SELECT id FROM executions ORDER BY started_at DESC LIMIT 1) ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []findings.Finding
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return nil, err
		}
		var f findings.Finding
		if err := json.Unmarshal(b, &f); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}
func (s *Store) GetFinding(ctx context.Context, id string) (findings.Finding, error) {
	var b []byte
	err := s.db.QueryRowContext(ctx, `SELECT finding_json FROM findings WHERE id=? ORDER BY observed_at DESC LIMIT 1`, id).Scan(&b)
	if err != nil {
		return findings.Finding{}, err
	}
	var f findings.Finding
	err = json.Unmarshal(b, &f)
	return f, err
}
func (s *Store) GraphForFinding(ctx context.Context, id string) (map[string]any, error) {
	var typ, status, source string
	var data []byte
	err := s.db.QueryRowContext(ctx, `SELECT type,status,source,data_json FROM graph_nodes WHERE id=?`, id).Scan(&typ, &status, &source, &data)
	if err != nil {
		return nil, err
	}
	var d any
	_ = json.Unmarshal(data, &d)
	edgeRows, err := s.db.QueryContext(ctx, `SELECT e.id,e.source_id,e.target_id,e.type,e.status,e.provenance_json,n.type,n.status,n.source,n.data_json FROM graph_edges e JOIN graph_nodes n ON n.id=CASE WHEN e.source_id=? THEN e.target_id ELSE e.source_id END WHERE e.source_id=? OR e.target_id=? ORDER BY e.id`, id, id, id)
	if err != nil {
		return nil, err
	}
	defer edgeRows.Close()
	edges := []any{}
	for edgeRows.Next() {
		var eid, src, dst, et, es, nt, ns, nsource string
		var prov, nodeData []byte
		if err := edgeRows.Scan(&eid, &src, &dst, &et, &es, &prov, &nt, &ns, &nsource, &nodeData); err != nil {
			return nil, err
		}
		var p, nd any
		_ = json.Unmarshal(prov, &p)
		_ = json.Unmarshal(nodeData, &nd)
		edges = append(edges, map[string]any{"id": eid, "sourceId": src, "targetId": dst, "type": et, "status": es, "provenance": p, "relatedNode": map[string]any{"type": nt, "status": ns, "source": nsource, "data": nd}})
	}
	return map[string]any{"node": map[string]any{"id": id, "type": typ, "status": status, "source": source, "data": d}, "edges": edges}, edgeRows.Err()
}
func (s *Store) LatestExecutionID(ctx context.Context) (string, error) {
	var id string
	err := s.db.QueryRowContext(ctx, `SELECT id FROM executions ORDER BY started_at DESC LIMIT 1`).Scan(&id)
	return id, err
}

func (s *Store) GetAICache(ctx context.Context, key string) ([]byte, bool, error) {
	var b []byte
	err := s.db.QueryRowContext(ctx, `SELECT response_json FROM ai_cache WHERE cache_key=?`, key).Scan(&b)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return b, true, nil
}

func (s *Store) PutAICache(ctx context.Context, key string, response []byte, modelDigest, promptVersion, schemaVersion string) error {
	_, err := s.db.ExecContext(ctx, `INSERT OR REPLACE INTO ai_cache(cache_key,response_json,model_digest,prompt_version,schema_version,created_at) VALUES(?,?,?,?,?,?)`, key, response, modelDigest, promptVersion, schemaVersion, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) SaveInvariantHypothesis(ctx context.Context, findingID, modelDigest, cacheKey string, invariant any) (string, error) {
	b, err := json.Marshal(invariant)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte(findingID+"\x00"+modelDigest+"\x00"), b...))
	id := "hypothesis:sha256:" + hex.EncodeToString(sum[:])
	edgeSum := sha256.Sum256([]byte(findingID + "\x00SUPPORTS\x00" + id))
	edgeID := "edge:sha256:" + hex.EncodeToString(edgeSum[:])
	prov, _ := json.Marshal(map[string]any{"sourceFindingId": findingID, "modelDigest": modelDigest, "cacheKey": cacheKey, "validation": "caphe strict invariant schema"})
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO graph_nodes(id,type,status,source,artifact_digest,data_json) VALUES(?,?,?,?,?,?)`, id, "SecurityInvariant", "hypothesized", "ai.infer_security_invariant", "", b); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO graph_edges(id,source_id,target_id,type,status,provenance_json) VALUES(?,?,?,?,?,?)`, edgeID, findingID, id, "SUPPORTS", "hypothesized", prov); err != nil {
		return "", err
	}
	return id, tx.Commit()
}
