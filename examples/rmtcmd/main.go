// Command rmtcmd connects to an IBM i as-rmtcmd host server and either runs
// a CL command or calls a program with parameters, printing the return
// code, any messages the server attached, and (for a program call) each
// output/inout parameter's returned data.
//
// Run a CL command:
//
//	go run ./examples/rmtcmd -host H -user U -password P -command "WRKACTJOB"
//
// Call a program (QCMDEXC, which itself runs a CL command string passed as
// its first parameter, is a convenient one to try this against):
//
//	go run ./examples/rmtcmd -host H -user U -password P \
//	  -program QCMDEXC -pgmlib QSYS \
//	  -param "input:20:WRKACTJOB" -param "input:4:0000"
//
// -program's RunCommand path requires server datastream level 10+ (IBM i
// V6R1/2008 or later) — see rmtcmd/wire.go for why. Password can also be
// supplied via JT400_PASSWORD instead of -password.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"jt400-go/as400"
	"jt400-go/as400/auth"
	"jt400-go/rmtcmd"
)

type paramFlag []string

func (p *paramFlag) String() string { return strings.Join(*p, ",") }
func (p *paramFlag) Set(s string) error {
	*p = append(*p, s)
	return nil
}

func main() {
	host := flag.String("host", "", "IBM i system hostname or IP address (required)")
	user := flag.String("user", "", "user profile to sign on with (required)")
	password := flag.String("password", "", "password (or set JT400_PASSWORD instead)")
	useTLS := flag.Bool("tls", false, "connect to the SSL port (9475) instead of plain (8475)")
	timeout := flag.Duration("timeout", 10*time.Second, "connection timeout")
	command := flag.String("command", "", "run this CL command string")
	program := flag.String("program", "", "call this program (with -pgmlib)")
	pgmLib := flag.String("pgmlib", "", "library containing -program")
	var params paramFlag
	flag.Var(&params, "param", "program parameter as usage:maxlen[:data], repeatable; usage is input/output/inout/null")
	flag.Parse()

	if *host == "" || *user == "" {
		fail("usage: rmtcmd -host <host> -user <user> [-password <password>] [-tls] " +
			"(-command <cl command> | -program <name> -pgmlib <lib> [-param usage:maxlen[:data]]...)")
	}
	if (*command == "") == (*program == "") {
		fail("specify exactly one of -command or -program")
	}

	pw := *password
	if pw == "" {
		pw = os.Getenv("JT400_PASSWORD")
	}
	if pw == "" {
		fail("no password given (use -password or set JT400_PASSWORD)")
	}

	var callParams []*rmtcmd.Parameter
	if *program != "" {
		var err error
		callParams, err = parseParams(params)
		if err != nil {
			fail(err.Error())
		}
	}

	opts := as400.DialOptions{Host: *host, Timeout: *timeout}
	if *useTLS {
		opts.TLSConfig = &tls.Config{ServerName: *host}
	}

	client, err := rmtcmd.Connect(opts, *user, pw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	var messages []rmtcmd.Message
	var callErr error
	if *command != "" {
		messages, callErr = client.RunCommand(*command, rmtcmd.MessageOptionUpTo10)
	} else {
		messages, callErr = client.CallProgram(*pgmLib, *program, callParams, rmtcmd.MessageOptionUpTo10)
	}

	for _, m := range messages {
		fmt.Printf("[%s] severity=%d type=%d %s\n", m.ID, m.Severity, m.Type, m.Text)
	}
	for i, p := range callParams {
		if p.Usage == rmtcmd.Output || p.Usage == rmtcmd.InOut {
			// Program parameters carry raw, uninterpreted bytes — IBM i host
			// programs hold character/numeric data in EBCDIC, so decode it
			// for display. auth.DecodeEBCDICLossy shows '?' for any byte
			// outside this library's restricted EBCDIC set (letters,
			// digits, space, $ # @) — expected for binary/packed-decimal
			// parameters, which aren't plain text to begin with.
			fmt.Printf("param %d output: %q (% X) [ebcdic: %q]\n",
				i, p.OutputData, p.OutputData, auth.DecodeEBCDICLossy(p.OutputData))
		}
	}

	if callErr != nil {
		fmt.Fprintf(os.Stderr, "failed: %v\n", callErr)
		os.Exit(1)
	}
	fmt.Println("success")
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(2)
}

func parseParams(specs []string) ([]*rmtcmd.Parameter, error) {
	params := make([]*rmtcmd.Parameter, 0, len(specs))
	for _, spec := range specs {
		parts := strings.SplitN(spec, ":", 3)
		if len(parts) < 2 {
			return nil, fmt.Errorf("invalid -param %q: want usage:maxlen[:data]", spec)
		}
		var usage rmtcmd.ParamUsage
		switch strings.ToLower(parts[0]) {
		case "input":
			usage = rmtcmd.Input
		case "output":
			usage = rmtcmd.Output
		case "inout":
			usage = rmtcmd.InOut
		case "null":
			usage = rmtcmd.Null
		default:
			return nil, fmt.Errorf("invalid -param %q: usage must be input/output/inout/null", spec)
		}
		maxLen, err := strconv.Atoi(parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid -param %q: maxlen must be an integer: %w", spec, err)
		}
		var data []byte
		if len(parts) == 3 && parts[2] != "" {
			// Host program parameters hold character/numeric data in
			// EBCDIC, blank-padded to the field's declared length — not
			// raw ASCII bytes — so encode -param's text data the same way.
			// This only covers this library's restricted EBCDIC set
			// (letters, digits, space, $ # @); binary or packed-decimal
			// parameters aren't representable through this text-based flag.
			data, err = auth.EncodeEBCDICPadded(strings.ToUpper(parts[2]), maxLen)
			if err != nil {
				return nil, fmt.Errorf("invalid -param %q: %w", spec, err)
			}
		}
		params = append(params, &rmtcmd.Parameter{
			Usage:     usage,
			MaxLength: int32(maxLen),
			InputData: data,
		})
	}
	return params, nil
}
