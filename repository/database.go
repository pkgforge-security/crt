package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/pkgforge-security/crt/result"
	_ "github.com/lib/pq"
)

var (
	driver  = "postgres"
	host    = "crt.sh"
	port    = 5432
	user    = "guest"
	dbname  = "certwatch"
	login   = fmt.Sprintf("host=%s port=%d user=%s dbname=%s", host, port, user, dbname)

	maxRetries   = 3
	initialDelay = 2 * time.Second
	maxDelay     = 10 * time.Second
)

type Repository struct {
	db *sql.DB
}

// logf prints messages only if quiet mode is disabled
func logf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
}

func New() (*Repository, error) {
	startTime := time.Now()

	db, err := sql.Open(driver, login+" connect_timeout=20")
	if err != nil {
		return nil, fmt.Errorf("Failed to Initialize DB Connection: %w", err)
	}

	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(10)

	var lastErr error
	delay := initialDelay

	for retries := 0; retries < maxRetries; retries++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		lastErr = db.PingContext(ctx)
		cancel()

		if lastErr == nil {
			logf("📡 Connected ==> [%s] (%v)\n", login, time.Since(startTime))
			return &Repository{db}, nil
		}

		logf("⚠️ Connection attempt %d Failed: %v\n", retries+1, lastErr)

		if retries < maxRetries-1 {
			// Add jitter (randomized wait time to avoid synchronized retries)
			jitter := time.Duration(rand.Int63n(int64(delay / 2)))
			sleepTime := delay + jitter
			time.Sleep(sleepTime)

			// Ensure delay does not exceed maxDelay
			delay = min(delay*2, maxDelay)
		}
	}

	db.Close()
	logf("❌ Connection Failed after %v\n", time.Since(startTime))
	return nil, fmt.Errorf("Failed to connect to database after %d attempts: %w", maxRetries, lastErr)
}

// min returns the smaller of two durations
func min(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

// sanitizeDomain ensures the domain is safe for SQL queries by escaping `%`
func sanitizeDomain(domain string) string {
	return strings.ReplaceAll(domain, "%", "\\%")
}

func (r *Repository) GetCertLogs(domain string, expired bool, limit int) (result.Certificates, error) {
	startTime := time.Now()

	if r.db == nil {
		return nil, errors.New("Database Connection is nil")
	}

	domain = sanitizeDomain(domain)
	filter := ""
	if expired {
		filter = excludeExpiredFilter
	}

	stmt := fmt.Sprintf(certLogScript, domain, domain, filter, limit)

	rows, err := r.db.Query(stmt)
	if err != nil {
		return nil, fmt.Errorf("Failed to query db: %w", err)
	}
	defer rows.Close()

	var res result.Certificates

	for rows.Next() {
		var cert result.Certificate
		var issuerCaID sql.NullInt32
		var id sql.NullInt64
		var issuerName, commonName, nameValue, serialNumber sql.NullString
		var entryTimestamp, notBefore, notAfter sql.NullTime

		err = rows.Scan(
			&issuerCaID,
			&issuerName,
			&commonName,
			&nameValue,
			&id,
			&entryTimestamp,
			&notBefore,
			&notAfter,
			&serialNumber,
		)
		if err != nil {
			return nil, fmt.Errorf("Failed to scan row: %w", err)
		}

		// Explicitly handle NULL values
		cert = result.Certificate{
			IssuerCaID:     0,
			IssuerName:     "",
			CommonName:     "",
			NameValue:      "",
			ID:             0,
			EntryTimestamp: time.Time{},
			NotBefore:      time.Time{},
			NotAfter:       time.Time{},
			SerialNumber:   "",
		}

		if issuerCaID.Valid {
			cert.IssuerCaID = int(issuerCaID.Int32)
		}
		if id.Valid {
			cert.ID = int(id.Int64)
		}
		if issuerName.Valid {
			cert.IssuerName = issuerName.String
		}
		if commonName.Valid {
			cert.CommonName = commonName.String
		}
		if nameValue.Valid {
			cert.NameValue = nameValue.String
		}
		if serialNumber.Valid {
			cert.SerialNumber = serialNumber.String
		}
		if entryTimestamp.Valid {
			cert.EntryTimestamp = entryTimestamp.Time
		}
		if notBefore.Valid {
			cert.NotBefore = notBefore.Time
		}
		if notAfter.Valid {
			cert.NotAfter = notAfter.Time
		}

		res = append(res, cert)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("Error iterating over rows: %w", err)
	}
	logf("⏳ Query GetCertLogs ==> %s (%v)\n", domain, time.Since(startTime))
	return res, nil
}

func (r *Repository) GetSubdomains(domain string, expired bool, limit int) (result.Subdomains, error) {
	startTime := time.Now()

	if r.db == nil {
		return nil, errors.New("Database connection is nil")
	}

	domain = sanitizeDomain(domain)
	filter := ""
	if expired {
		filter = excludeExpiredFilter
	}

	stmt := fmt.Sprintf(subdomainScript, domain, domain, filter, limit)

	rows, err := r.db.Query(stmt)
	if err != nil {
		return nil, fmt.Errorf("Failed to query row: %w", err)
	}
	defer rows.Close()

	var res result.Subdomains

	for rows.Next() {
		var subdmn sql.NullString

		if err = rows.Scan(&subdmn); err != nil {
			return nil, fmt.Errorf("Failed to scan row: %w", err)
		}

		if subdmn.Valid {
			res = append(res, result.Subdomain{Name: subdmn.String})
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("Error iterating over rows: %w", err)
	}

	logf("⏳ Query GetSubdomains ==> %s (%v)\n", domain, time.Since(startTime))

	return res, nil
}

func (r *Repository) Close() error {
	if r.db == nil {
		return errors.New("Database connection is already closed or nil")
	}
	return r.db.Close()
}