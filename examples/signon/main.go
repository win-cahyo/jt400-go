// Command signon connects to an IBM i as-signon host server and
// authenticates, printing what the server returns on success.
//
// Usage:
//
//	go run ./examples/signon -host myibmi.example.com -user MYUSER -password 'secret'
//
// The password can also be supplied via the JT400_PASSWORD environment
// variable instead of -password, to keep it out of shell history and
// process listings.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"time"

	"jt400-go/as400"
	"jt400-go/signon"
)

func main() {
	host := flag.String("host", "", "IBM i system hostname or IP address (required)")
	user := flag.String("user", "", "user profile to sign on with (required)")
	password := flag.String("password", "", "password (or set JT400_PASSWORD instead)")
	useTLS := flag.Bool("tls", false, "connect to the SSL port (9476) instead of plain (8476)")
	timeout := flag.Duration("timeout", 10*time.Second, "connection timeout")
	flag.Parse()

	if *host == "" || *user == "" {
		fmt.Fprintln(os.Stderr, "usage: signon -host <host> -user <user> [-password <password>] [-tls]")
		flag.PrintDefaults()
		os.Exit(2)
	}

	pw := *password
	if pw == "" {
		pw = os.Getenv("JT400_PASSWORD")
	}
	if pw == "" {
		fmt.Fprintln(os.Stderr, "error: no password given (use -password or set JT400_PASSWORD)")
		os.Exit(2)
	}

	opts := as400.DialOptions{Host: *host, Timeout: *timeout}
	if *useTLS {
		opts.TLSConfig = &tls.Config{ServerName: *host}
	}

	client, err := signon.Connect(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	fmt.Printf("negotiated password level: %d\n", client.PasswordLevel())

	info, err := client.Authenticate(*user, pw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "authenticate: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("signon successful")
	fmt.Printf("  user ID:          %s\n", info.UserID)
	fmt.Printf("  server CCSID:     %d\n", info.ServerCCSID)
	fmt.Printf("  current signon:   %s\n", formatTime(info.CurrentSignonDate))
	fmt.Printf("  last signon:      %s\n", formatTime(info.LastSignonDate))
	fmt.Printf("  password expires: %s\n", formatTime(info.ExpirationDate))
	if info.PasswordExpirationWarningDays > 0 {
		fmt.Printf("  password expiration warning: %d day(s)\n", info.PasswordExpirationWarningDays)
	}
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "(not returned)"
	}
	return t.Format("2006-01-02 15:04:05")
}
