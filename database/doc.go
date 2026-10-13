// Package database implements a client for the IBM i as-database host
// server (TCP 8471 / SSL 9471) — the SQL interface JTOpen's JDBC driver
// (AS400JDBCConnection) speaks — covering prepared statements with
// parameter markers, forward-only cursors, row counts, and commit/rollback.
//
// It can be used directly (Connect, Conn.Prepare, Stmt.Exec/Query) or
// through database/sql: importing this package registers the "jt400"
// driver, and NewConnector builds a driver.Connector for sql.OpenDB.
//
// Scope, deliberately narrower than JTOpen's JDBC driver:
//
//   - Data types: CHAR/VARCHAR/LONG VARCHAR (and FOR BIT DATA), GRAPHIC/
//     VARGRAPHIC in a UTF-16 CCSID, BINARY/VARBINARY, SMALLINT/INTEGER/
//     BIGINT, REAL/DOUBLE, DECIMAL (packed) and NUMERIC (zoned), DATE/TIME/
//     TIMESTAMP, and LOB columns small enough to come back inline. LOB
//     locators, DECFLOAT, XML, arrays and BOOLEAN are rejected with an error.
//   - Cursors are forward-only and read-only. Stored procedure result sets
//     are not returned (CALL works, but only as an Exec).
//   - No SQL packages, no batch execution, no scrollable cursors, no
//     request/reply RLE compression, no library-list management (set the
//     default schema instead, or call QSYS2.QCMDEXC to run ADDLIBLE).
//
// Character data is converted client-side, as JTOpen does, using the CCSID
// the server describes for each column or parameter. CCSIDs 37, 1047, 1140
// (EBCDIC), 1200/13488 (UTF-16) and 1208 (UTF-8) are built in; register
// others with RegisterCCSID before connecting.
package database
