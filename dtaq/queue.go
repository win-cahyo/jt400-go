package dtaq

import "fmt"

// Queue is a handle to a single named data queue (library/name), used for
// both plain and keyed queues.
type Queue struct {
	client  *Client
	library string
	name    string
}

// Create creates the queue. Fails with an *Error wrapping CPF9870 if it
// already exists.
func (q *Queue) Create(opts CreateOptions) error {
	req, err := buildCreateRequest(q.library, q.name, opts)
	if err != nil {
		return err
	}
	reply, err := q.client.conn.Call(req)
	if err != nil {
		return fmt.Errorf("dtaq: create %s/%s: %w", q.library, q.name, err)
	}
	return checkCommonReply(reply)
}

// Delete deletes the queue.
func (q *Queue) Delete() error {
	req, err := buildQueueOnlyRequest(0x0004, q.library, q.name)
	if err != nil {
		return err
	}
	reply, err := q.client.conn.Call(req)
	if err != nil {
		return fmt.Errorf("dtaq: delete %s/%s: %w", q.library, q.name, err)
	}
	return checkCommonReply(reply)
}

// Clear removes every entry from the queue.
func (q *Queue) Clear() error { return q.clear(nil, false) }

// ClearKey removes every entry matching key from a keyed queue.
func (q *Queue) ClearKey(key []byte) error { return q.clear(key, true) }

func (q *Queue) clear(key []byte, hasKey bool) error {
	req, err := buildClearRequest(q.library, q.name, key, hasKey)
	if err != nil {
		return err
	}
	reply, err := q.client.conn.Call(req)
	if err != nil {
		return fmt.Errorf("dtaq: clear %s/%s: %w", q.library, q.name, err)
	}
	return checkCommonReply(reply)
}

// Write adds data as an entry on a plain (non-keyed) queue.
func (q *Queue) Write(data []byte) error { return q.write(nil, data) }

// WriteKeyed adds data as an entry tagged with key on a keyed queue.
func (q *Queue) WriteKeyed(key, data []byte) error { return q.write(key, data) }

func (q *Queue) write(key, data []byte) error {
	req, err := buildWriteRequest(q.library, q.name, key, data)
	if err != nil {
		return err
	}
	reply, err := q.client.conn.Call(req)
	if err != nil {
		return fmt.Errorf("dtaq: write %s/%s: %w", q.library, q.name, err)
	}
	return checkCommonReply(reply)
}

// Read receives (or, if peek is true, looks at without removing) the next
// entry from a plain queue, waiting up to waitSeconds seconds for one to
// arrive (0 = don't wait, -1 = wait indefinitely). It returns a nil *Entry
// with a nil error if no entry became available within the wait time.
func (q *Queue) Read(waitSeconds int32, peek bool) (*Entry, error) {
	req, err := buildReadRequest(q.library, q.name, false, "", nil, waitSeconds, peek)
	if err != nil {
		return nil, err
	}
	reply, err := q.client.conn.Call(req)
	if err != nil {
		return nil, fmt.Errorf("dtaq: read %s/%s: %w", q.library, q.name, err)
	}
	return parseReadReply(reply)
}

// ReadKeyed receives (or, if peek is true, looks at without removing) the
// next entry from a keyed queue matching key under searchType, waiting up
// to waitSeconds seconds (0 = don't wait, -1 = wait indefinitely). It
// returns a nil *Entry with a nil error if no matching entry became
// available within the wait time.
func (q *Queue) ReadKeyed(searchType SearchType, key []byte, waitSeconds int32, peek bool) (*Entry, error) {
	req, err := buildReadRequest(q.library, q.name, true, searchType, key, waitSeconds, peek)
	if err != nil {
		return nil, err
	}
	reply, err := q.client.conn.Call(req)
	if err != nil {
		return nil, fmt.Errorf("dtaq: read keyed %s/%s: %w", q.library, q.name, err)
	}
	return parseReadReply(reply)
}

// Attributes retrieves the queue's configuration.
func (q *Queue) Attributes() (*Attributes, error) {
	req, err := buildQueueOnlyRequest(0x0001, q.library, q.name)
	if err != nil {
		return nil, err
	}
	reply, err := q.client.conn.Call(req)
	if err != nil {
		return nil, fmt.Errorf("dtaq: attributes %s/%s: %w", q.library, q.name, err)
	}
	return parseAttributesReply(reply)
}
