// Package dbcreds tries default credentials against common database services.
// MySQL, Postgres, MSSQL, Redis, MongoDB. Connect with empty/default creds and
// fetch a version string on success.
package dbcreds

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"time"

	"github.com/chud-lori/ngehe/internal/finding"
	mssql "github.com/microsoft/go-mssqldb"
	redis "github.com/redis/go-redis/v9"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
)

// Use mssql import (consumed for side-effect driver registration).
var _ = mssql.NewConnectorWithAccessTokenProvider

func Scan(host string, port int, service string) []finding.Finding {
	switch service {
	case "mysql", "mariadb":
		return tryMySQL(host, port)
	case "postgresql", "postgres":
		return tryPostgres(host, port)
	case "ms-sql-s", "mssql":
		return tryMSSQL(host, port)
	case "redis":
		return tryRedis(host, port)
	}
	return nil
}

func tryMySQL(host string, port int) []finding.Finding {
	if port == 0 {
		port = 3306
	}
	creds := [][2]string{{"root", ""}, {"root", "root"}, {"root", "password"}, {"admin", "admin"}, {"mysql", "mysql"}}
	for _, c := range creds {
		dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/?timeout=3s", c[0], c[1], host, port)
		db, err := sql.Open("mysql", dsn)
		if err != nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		if err := db.PingContext(ctx); err == nil {
			version := queryScalar(db, ctx, "SELECT VERSION()")
			cancel()
			db.Close()
			return []finding.Finding{{
				Rule: "db-default-creds-mysql", Severity: finding.SevCritical,
				Method: "TCP", URL: fmt.Sprintf("mysql://%s:%d", host, port), Path: "/",
				Param:    "creds",
				Payload:  c[0] + ":" + c[1],
				Evidence: "VERSION(): " + version,
				Why:      "MySQL accepted default credentials",
			}}
		}
		cancel()
		db.Close()
	}
	return nil
}

func tryPostgres(host string, port int) []finding.Finding {
	if port == 0 {
		port = 5432
	}
	creds := [][2]string{{"postgres", ""}, {"postgres", "postgres"}, {"postgres", "password"}, {"admin", "admin"}}
	for _, c := range creds {
		dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=postgres sslmode=disable connect_timeout=3", host, port, c[0], c[1])
		db, err := sql.Open("postgres", dsn)
		if err != nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		if err := db.PingContext(ctx); err == nil {
			version := queryScalar(db, ctx, "SELECT VERSION()")
			cancel()
			db.Close()
			return []finding.Finding{{
				Rule: "db-default-creds-postgres", Severity: finding.SevCritical,
				Method: "TCP", URL: fmt.Sprintf("postgres://%s:%d", host, port), Path: "/",
				Param:    "creds",
				Payload:  c[0] + ":" + c[1],
				Evidence: "VERSION(): " + version,
				Why:      "PostgreSQL accepted default credentials",
			}}
		}
		cancel()
		db.Close()
	}
	return nil
}

func tryMSSQL(host string, port int) []finding.Finding {
	if port == 0 {
		port = 1433
	}
	creds := [][2]string{{"sa", ""}, {"sa", "sa"}, {"sa", "password"}, {"sa", "Password1"}, {"admin", "admin"}}
	for _, c := range creds {
		dsn := fmt.Sprintf("server=%s;port=%d;user id=%s;password=%s;encrypt=disable;connection timeout=3", host, port, c[0], c[1])
		db, err := sql.Open("sqlserver", dsn)
		if err != nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		if err := db.PingContext(ctx); err == nil {
			version := queryScalar(db, ctx, "SELECT @@VERSION")
			cancel()
			db.Close()
			return []finding.Finding{{
				Rule: "db-default-creds-mssql", Severity: finding.SevCritical,
				Method: "TCP", URL: fmt.Sprintf("mssql://%s:%d", host, port), Path: "/",
				Param:    "creds",
				Payload:  c[0] + ":" + c[1],
				Evidence: truncate(version, 200),
				Why:      "MSSQL accepted default credentials — try xp_cmdshell for RCE",
			}}
		}
		cancel()
		db.Close()
	}
	return nil
}

func tryRedis(host string, port int) []finding.Finding {
	if port == 0 {
		port = 6379
	}
	rdb := redis.NewClient(&redis.Options{
		Addr:        net.JoinHostPort(host, fmt.Sprint(port)),
		DialTimeout: 3 * time.Second,
		ReadTimeout: 3 * time.Second,
	})
	defer rdb.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	info, err := rdb.Info(ctx, "server").Result()
	if err == nil {
		return []finding.Finding{{
			Rule: "db-no-auth-redis", Severity: finding.SevCritical,
			Method: "TCP", URL: fmt.Sprintf("redis://%s:%d", host, port), Path: "/",
			Evidence: truncate(info, 200),
			Why:      "Redis allowed INFO with no authentication — full data access; try CONFIG SET for RCE via module load",
		}}
	}
	return nil
}

func queryScalar(db *sql.DB, ctx context.Context, q string) string {
	var v string
	row := db.QueryRowContext(ctx, q)
	if err := row.Scan(&v); err != nil {
		return ""
	}
	return v
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
