// Command database connects to an IBM i as-database host server and runs
// one SQL statement, printing the result rows (for a query) or the number
// of rows affected (for anything else).
//
// Query, with ? parameter markers bound by -arg (repeatable, in order):
//
//	go run ./examples/database -host H -user U -password P \
//	  -sql "SELECT TRX_ID, STATUS FROM QGPL.CMSBULK WHERE TR_DATE = ?" -arg 20261013
//
// A statement that is safe to try first, on any system:
//
//	go run ./examples/database -host H -user U -sql "VALUES (CURRENT TIMESTAMP, CURRENT SERVER)"
//
// Password can also be supplied via JT400_PASSWORD instead of -password.
// -arg values are sent as strings and converted by the server-described
// parameter type; use -null for an SQL NULL argument at that position.
package main

import (
	"context"
	"crypto/tls"
	"database/sql/driver"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/win-cahyo/jt400-go/as400"
	"github.com/win-cahyo/jt400-go/database"
)

type argFlag []any

func (a *argFlag) String() string { return fmt.Sprint(*a) }
func (a *argFlag) Set(s string) error {
	*a = append(*a, s)
	return nil
}

type nullFlag struct{ args *argFlag }

func (n nullFlag) String() string   { return "" }
func (n nullFlag) IsBoolFlag() bool { return true }
func (n nullFlag) Set(string) error {
	*n.args = append(*n.args, nil)
	return nil
}

func main() {
	host := flag.String("host", "", "IBM i system hostname or IP address (required)")
	user := flag.String("user", "", "user profile to sign on with (required)")
	password := flag.String("password", "", "password (or set JT400_PASSWORD instead)")
	useTLS := flag.Bool("tls", false, "connect to the SSL port (9471) instead of plain (8471)")
	timeout := flag.Duration("timeout", 10*time.Second, "connection timeout")
	ioTimeout := flag.Duration("iotimeout", 60*time.Second, "timeout for each request to the server")
	query := flag.String("sql", "", "SQL statement to run (required)")
	systemNaming := flag.Bool("system-naming", false, "use system naming (LIB/FILE) instead of SQL naming")
	schema := flag.String("schema", "", "default schema for unqualified names")
	var args argFlag
	flag.Var(&args, "arg", "value for the next ? parameter marker, repeatable")
	flag.Var(nullFlag{&args}, "null", "SQL NULL for the next ? parameter marker, repeatable")
	flag.Parse()

	if *host == "" || *user == "" || *query == "" {
		fail("usage: database -host <host> -user <user> [-password <password>] [-tls] -sql <statement> [-arg value | -null]...")
	}
	pw := *password
	if pw == "" {
		pw = os.Getenv("JT400_PASSWORD")
	}
	if pw == "" {
		fail("no password given (use -password or set JT400_PASSWORD)")
	}

	dial := as400.DialOptions{Host: *host, Timeout: *timeout, IOTimeout: *ioTimeout}
	if *useTLS {
		dial.TLSConfig = &tls.Config{ServerName: *host}
	}
	conn, err := database.Connect(dial, *user, pw, database.Options{
		SystemNaming:  *systemNaming,
		DefaultSchema: *schema,
		Location:      time.Local,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()
	fmt.Printf("connected: server CCSID %d, VRM %#06x, job %s\n", conn.ServerCCSID(), conn.VRM(), conn.JobID())

	ctx := context.Background()
	st, err := conn.Prepare(ctx, *query)
	if err != nil {
		fmt.Fprintf(os.Stderr, "prepare: %v\n", err)
		os.Exit(1)
	}
	defer st.Close()

	if !st.ReturnsRows() {
		res, err := st.Exec(ctx, args...)
		if err != nil {
			fmt.Fprintf(os.Stderr, "execute: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("%d row(s) affected\n", res.RowsAffected)
		return
	}

	rows, err := st.Query(ctx, args...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "query: %v\n", err)
		os.Exit(1)
	}
	defer rows.Close()

	var header []string
	for _, ct := range rows.ColumnTypes() {
		header = append(header, fmt.Sprintf("%s %s", ct.Name, ct.TypeName))
	}
	fmt.Println(strings.Join(header, " | "))

	n := 0
	for {
		dest := make([]driver.Value, len(header))
		if err := rows.Next(dest); err == io.EOF {
			break
		} else if err != nil {
			fmt.Fprintf(os.Stderr, "fetch: %v\n", err)
			os.Exit(1)
		}
		cells := make([]string, len(dest))
		for i, v := range dest {
			switch x := v.(type) {
			case nil:
				cells[i] = "NULL"
			case []byte:
				cells[i] = fmt.Sprintf("x'%X'", x)
			case time.Time:
				cells[i] = x.Format(time.RFC3339Nano)
			default:
				cells[i] = fmt.Sprintf("%q", fmt.Sprint(x))
			}
		}
		fmt.Println(strings.Join(cells, " | "))
		n++
	}
	fmt.Printf("%d row(s)\n", n)
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(2)
}
