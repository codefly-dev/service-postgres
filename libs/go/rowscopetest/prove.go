// Package rowscopetest proves, against a real database, that one row-confined
// table holds the row-confinement model for every Binding: it seeds random
// rows across partitions, scopes and principals through the fixture principal,
// then acts and asserts through a postgres.Store on the real runtime logins,
// and compares everything the database returns or changes with a model that
// knows nothing about SQL.
//
// The model has four parts: the mode (whose rows), the access (whether it may
// write at all), the write mode and the write reach (whose rows and which
// scopes it may write, when that is less than what it reads). A Read binding
// is attacked as well as exercised: on the reader's own login, in a READ WRITE
// transaction, with every setting a writer would have, each write must be
// permission denied, and so must assuming a write role.
//
// A module calls Prove from its own suite, once per row-confined table, on a
// migrated disposable database. It is the half of the evidence the catalog
// gate (migrationtest.CheckRowScope) cannot give: the gate checks that the
// policies are there, this checks what they let through.
package rowscopetest

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"sort"
	"strings"
	"time"

	postgres "github.com/codefly-dev/service-postgres/libs/go"
	"github.com/codefly-dev/service-postgres/libs/go/rowscope"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Proof names the table and the principals of one proof.
type Proof struct {
	// Fixture is a connection that bypasses row security: the run's
	// fixture-connection. It seeds and inspects; it never asserts isolation.
	Fixture string
	// ReadOnly and ReadWrite are the runtime logins' connections, the ones
	// the service itself opens its Store on.
	ReadOnly  string
	ReadWrite string
	// Roles are the store's roles. The read and the write role of both modes
	// are required: the proof compares the modes and the accesses, and a store
	// on the two-role form does not hold the model it proves.
	Roles postgres.Roles
	// Options are the Store options the service uses, and Settings the names
	// its policies read, when they are not the defaults.
	Options  []postgres.Option
	Settings rowscope.Settings
	// Table is the table under proof.
	Table rowscope.Table
	// Key is a column that identifies a row and that the database fills on
	// insert. It is read as text. Default "id".
	Key string
	// Body is a text column listed in Table.Mutable that the proof overwrites.
	Body string
	// Values supplies the table's other columns that an INSERT must name.
	Values map[string]any
	// Partitions, Scopes, Principals, Rows and Rounds size the proof; zero
	// means 3, 4, 5, 300 and 250. Seed zero means a fresh one, which is logged.
	Partitions, Scopes, Principals, Rows, Rounds int
	Seed                                         uint64
}

// Reporter is the part of testing.TB the proof uses.
type Reporter interface {
	Helper()
	Logf(format string, arguments ...any)
	Fatalf(format string, arguments ...any)
	Cleanup(func())
}

type row struct {
	partition, scope, principal string
	shared                      bool
	body                        string
}

type bindingKey struct{}

// Prove fails t on the first Binding for which the table returns or changes a
// row the model says it may not, or withholds one it must return.
func Prove(t Reporter, proof Proof) {
	t.Helper()
	if proof.Fixture == "" || proof.ReadOnly == "" || proof.ReadWrite == "" {
		t.Fatalf("rowscopetest: the fixture, read-only and read-write connections are required")
	}
	if proof.Table.Name == "" || proof.Body == "" {
		t.Fatalf("rowscopetest: the table and its body column are required")
	}
	if proof.Roles.StrictRead == "" || proof.Roles.StrictWrite == "" || proof.Roles.PrivilegedRead == "" || proof.Roles.PrivilegedWrite == "" {
		t.Fatalf("rowscopetest: the read and the write role of both modes are required (Roles.StrictRead, StrictWrite, PrivilegedRead, PrivilegedWrite); with one role per mode a Read binding's transaction holds the write grants, and READ ONLY is all that refuses its write")
	}
	if proof.Roles.Strict != "" || proof.Roles.Privileged != "" {
		t.Fatalf("rowscopetest: name the four roles alone; Roles.Strict and Roles.Privileged are the two-role form")
	}
	p := prover{t: t, proof: proof, model: map[string]row{}}
	p.defaults()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)
	p.ctx = ctx

	fixture, err := pgx.Connect(ctx, proof.Fixture)
	if err != nil {
		t.Fatalf("rowscopetest: connect as the fixture principal: %v", err)
	}
	p.fixture = fixture
	// Around the Store, as the reader's login itself: where a Read binding's
	// writes are attempted with nothing but the database in the way.
	reader, err := pgx.Connect(ctx, proof.ReadOnly)
	if err != nil {
		t.Fatalf("rowscopetest: connect as the read-only runtime login: %v", err)
	}
	p.reader = reader
	t.Cleanup(func() { _ = reader.Close(context.Background()) })
	t.Cleanup(func() {
		// The proof's partitions are its own; nothing else is touched.
		_, _ = fixture.Exec(context.Background(), `DELETE FROM `+p.table+` WHERE `+p.partition+` = ANY($1)`, p.partitions)
		_ = fixture.Close(context.Background())
	})
	binder := postgres.BinderFunc(func(ctx context.Context) (postgres.Binding, error) {
		binding, ok := ctx.Value(bindingKey{}).(postgres.Binding)
		if !ok {
			return postgres.Binding{}, errors.New("this call carries no binding")
		}
		return binding, nil
	})
	store, closeStore, err := postgres.OpenStore(ctx, proof.ReadOnly, proof.ReadWrite, binder, proof.Roles, proof.Options...)
	if err != nil {
		t.Fatalf("rowscopetest: open the store on the runtime logins: %v", err)
	}
	t.Cleanup(closeStore)
	p.store = store

	p.seed()
	p.unbound()
	for round := range p.proof.Rounds {
		p.round(round)
	}
	p.unbound()
	t.Logf("rowscopetest: %s held over %d bindings: %d reads, %d writes accepted, %d refused, %d Read bindings attacked with %d writes all denied, %d rows at the end (seed %d)",
		p.table, p.proof.Rounds, p.reads, p.accepted, p.refused, p.readers, p.denied, len(p.model), p.proof.Seed)
}

type prover struct {
	t       Reporter
	ctx     context.Context
	proof   Proof
	random  *rand.Rand
	fixture *pgx.Conn
	reader  *pgx.Conn
	store   *postgres.Store

	table, key, partition, scope, principal, shared, body string
	partitions, scopes, principals                        []string
	model                                                 map[string]row
	reads, accepted, refused, readers, denied             int
}

func (p *prover) defaults() {
	size := func(value *int, fallback int) {
		if *value <= 0 {
			*value = fallback
		}
	}
	size(&p.proof.Partitions, 3)
	size(&p.proof.Scopes, 4)
	size(&p.proof.Principals, 5)
	size(&p.proof.Rows, 300)
	size(&p.proof.Rounds, 250)
	if p.proof.Seed == 0 {
		p.proof.Seed = rand.Uint64() | 1
	}
	if p.proof.Settings == (rowscope.Settings{}) {
		p.proof.Settings = rowscope.DefaultSettings()
	}
	if p.proof.Key == "" {
		p.proof.Key = "id"
	}
	p.random = rand.New(rand.NewPCG(p.proof.Seed, p.proof.Seed>>1))
	quote := func(identifier, fallback string) string {
		if identifier == "" {
			identifier = fallback
		}
		return pgx.Identifier{identifier}.Sanitize()
	}
	p.table = p.proof.Table.Qualified()
	p.key = quote(p.proof.Key, "id")
	p.partition = quote(p.proof.Table.Partition, "tenant")
	p.scope = quote(p.proof.Table.Scope, "scope")
	p.principal = quote(p.proof.Table.Principal, "principal")
	p.shared = quote(p.proof.Table.Shared, "shared")
	p.body = quote(p.proof.Body, "")
	// Names no other run and no real row has, so the model owns its partitions.
	run := fmt.Sprintf("proof%x", p.proof.Seed)
	for index := range p.proof.Partitions {
		p.partitions = append(p.partitions, fmt.Sprintf("%s-p%d", run, index))
	}
	for index := range p.proof.Scopes {
		p.scopes = append(p.scopes, fmt.Sprintf("%s-s%d", run, index))
	}
	for index := range p.proof.Principals {
		p.principals = append(p.principals, fmt.Sprintf("human:%s-%d", run, index))
	}
	// A scope's own principal is a principal like any other to the table.
	p.principals = append(p.principals, "agent:"+p.scopes[0])
}

func (p *prover) pick(from []string) string { return from[p.random.IntN(len(from))] }

func (p *prover) randomRow() row {
	return row{
		partition: p.pick(p.partitions), scope: p.pick(p.scopes), principal: p.pick(p.principals),
		shared: p.random.IntN(4) == 0, body: "seeded",
	}
}

func (p *prover) randomBinding() postgres.Binding {
	binding := postgres.Binding{Partition: p.pick(p.partitions), Principal: p.pick(p.principals), Mode: postgres.Strict, Actor: "service:rowscopetest"}
	if p.random.IntN(2) == 0 {
		binding.Mode = postgres.Privileged
	}
	for _, scope := range p.scopes {
		if p.random.IntN(3) == 0 {
			binding.Reach = append(binding.Reach, scope)
		}
	}
	// A scope that holds no row, and sometimes nothing else: a reach is not
	// widened by naming something that is not there.
	if len(binding.Reach) == 0 || p.random.IntN(6) == 0 {
		binding.Reach = append(binding.Reach, p.scopes[0]+"-absent")
	}
	if p.random.IntN(12) == 0 {
		binding.Partition += "-absent"
	}
	// The access, and what it writes when that is less than what it reads.
	if p.random.IntN(3) == 0 {
		binding.Access = postgres.Read
		return binding
	}
	binding.Access = postgres.ReadWrite
	if binding.Mode == postgres.Privileged && p.random.IntN(3) == 0 {
		binding.WriteMode = postgres.Strict
	}
	if p.random.IntN(2) == 0 {
		for _, scope := range binding.Reach {
			if p.random.IntN(2) == 0 {
				binding.WriteReach = append(binding.WriteReach, scope)
			}
		}
		if len(binding.WriteReach) == 0 {
			binding.WriteReach = []string{p.pick(binding.Reach)}
		}
	}
	return binding
}

// The model. It is the specification, and deliberately shares no code with
// the policies.

func reaches(binding postgres.Binding, candidate row) bool {
	return candidate.partition == binding.Partition && slices.Contains(binding.Reach, candidate.scope)
}

func mayRead(binding postgres.Binding, candidate row) bool {
	if !reaches(binding, candidate) {
		return false
	}
	return binding.Mode == postgres.Privileged || candidate.shared || candidate.principal == binding.Principal
}

// writeMode and writeReach are what the Binding writes with: its mode and its
// reach unless it names less.
func writeMode(binding postgres.Binding) postgres.Mode {
	if binding.WriteMode != 0 {
		return binding.WriteMode
	}
	return binding.Mode
}

func writeReach(binding postgres.Binding) []string {
	if binding.WriteReach != nil {
		return binding.WriteReach
	}
	return binding.Reach
}

func mayWrite(binding postgres.Binding, candidate row) bool {
	if binding.Access != postgres.ReadWrite || !reaches(binding, candidate) || !slices.Contains(writeReach(binding), candidate.scope) {
		return false
	}
	return writeMode(binding) == postgres.Privileged || candidate.principal == binding.Principal
}

// seesInWrite is what a write transaction reads: the whole reach, as the mode
// it writes in.
func seesInWrite(binding postgres.Binding, candidate row) bool {
	if binding.Access != postgres.ReadWrite || !reaches(binding, candidate) {
		return false
	}
	return writeMode(binding) == postgres.Privileged || candidate.shared || candidate.principal == binding.Principal
}

func (p *prover) expected(binding postgres.Binding, may func(postgres.Binding, row) bool) []string {
	var keys []string
	for key, candidate := range p.model {
		if may(binding, candidate) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func (p *prover) insertSQL() (string, []any) {
	columns := []string{p.partition, p.scope, p.principal, p.shared, p.body}
	var extra []any
	names := make([]string, 0, len(p.proof.Values))
	for name := range p.proof.Values {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		columns = append(columns, pgx.Identifier{name}.Sanitize())
		extra = append(extra, p.proof.Values[name])
	}
	placeholders := make([]string, len(columns))
	for index := range columns {
		placeholders[index] = fmt.Sprintf("$%d", index+1)
	}
	return `INSERT INTO ` + p.table + ` (` + strings.Join(columns, ", ") + `) VALUES (` + strings.Join(placeholders, ", ") + `) RETURNING ` + p.key + `::text`, extra
}

func (p *prover) insertArguments(candidate row, extra []any) []any {
	return append([]any{candidate.partition, candidate.scope, candidate.principal, candidate.shared, candidate.body}, extra...)
}

func (p *prover) seed() {
	p.t.Helper()
	statement, extra := p.insertSQL()
	for range p.proof.Rows {
		candidate := p.randomRow()
		var key string
		if err := p.fixture.QueryRow(p.ctx, statement, p.insertArguments(candidate, extra)...).Scan(&key); err != nil {
			p.t.Fatalf("rowscopetest: seed through the fixture principal: %v", err)
		}
		p.model[key] = candidate
	}
}

// unbound proves the three ways of having no Binding: the Store refuses to
// open a transaction, the bare login is refused the table, and a role assumed
// with nothing bound, or with an empty reach, sees and changes nothing.
func (p *prover) unbound() {
	p.t.Helper()
	nothing := func(context.Context, postgres.ReadTx) error {
		p.t.Fatalf("rowscopetest: a transaction opened without a complete binding")
		return nil
	}
	if err := p.store.Read(p.ctx, nothing); !errors.Is(err, postgres.ErrNoBinding) {
		p.t.Fatalf("rowscopetest: a call with no binding: %v, want ErrNoBinding", err)
	}
	empty := postgres.Binding{Partition: p.partitions[0], Principal: p.principals[0], Mode: postgres.Privileged}
	if err := p.store.Read(context.WithValue(p.ctx, bindingKey{}, empty), nothing); !errors.Is(err, postgres.ErrNoReach) {
		p.t.Fatalf("rowscopetest: an empty reach: %v, want ErrNoReach", err)
	}

	// Around the Store, as each runtime login itself: the read roles on the
	// reader's, the write roles on the writer's.
	raw, err := pgx.Connect(p.ctx, p.proof.ReadWrite)
	if err != nil {
		p.t.Fatalf("rowscopetest: connect as the runtime login: %v", err)
	}
	defer raw.Close(context.Background())
	settings := p.proof.Settings
	for _, login := range []struct {
		name   string
		conn   *pgx.Conn
		roles  []string
		writes bool
	}{
		{"read-only", p.reader, []string{p.proof.Roles.StrictRead, p.proof.Roles.PrivilegedRead}, false},
		{"read-write", raw, []string{p.proof.Roles.StrictWrite, p.proof.Roles.PrivilegedWrite}, true},
	} {
		if _, err := login.conn.Exec(p.ctx, `SELECT 1 FROM `+p.table); sqlState(err) != "42501" {
			p.t.Fatalf("rowscopetest: the %s runtime login read %s without assuming a role (SQLSTATE %q): it holds a privilege of its own", login.name, p.table, sqlState(err))
		}
		for _, role := range login.roles {
			// Nothing bound; everything bound except the reach; and, for a role
			// that writes, everything bound except the write reach.
			binds := [][]any{
				{`SELECT set_config('role', $1, true)`, role},
				{`SELECT set_config('role', $1, true), set_config($2, $3, true), set_config($4, $5, true), set_config($6, '', true), set_config($7, $8, true)`,
					role, settings.Partition, p.partitions[0], settings.Principal, p.principals[0], settings.Reach, settings.WriteReach, strings.Join(p.scopes, ",")},
			}
			if login.writes {
				binds = append(binds, []any{`SELECT set_config('role', $1, true), set_config($2, $3, true), set_config($4, $5, true), set_config($6, $7, true), set_config($8, '', true)`,
					role, settings.Partition, p.partitions[0], settings.Principal, p.principals[0], settings.Reach, strings.Join(p.scopes, ","), settings.WriteReach})
			}
			for index, bind := range binds {
				tx, err := login.conn.BeginTx(p.ctx, pgx.TxOptions{AccessMode: pgx.ReadWrite})
				if err != nil {
					p.t.Fatalf("rowscopetest: %v", err)
				}
				if _, err := tx.Exec(p.ctx, bind[0].(string), bind[1:]...); err != nil {
					p.t.Fatalf("rowscopetest: assume %s on the %s login: %v", role, login.name, err)
				}
				var seen int
				if err := tx.QueryRow(p.ctx, `SELECT count(*) FROM `+p.table).Scan(&seen); err != nil || (seen != 0 && index < 2) {
					p.t.Fatalf("rowscopetest: %s with no reach read %d rows (%v)", role, seen, err)
				}
				if login.writes {
					for _, statement := range []string{`UPDATE ` + p.table + ` SET ` + p.body + ` = 'unbound'`, `DELETE FROM ` + p.table} {
						if tag, err := tx.Exec(p.ctx, statement); err != nil || tag.RowsAffected() != 0 {
							p.t.Fatalf("rowscopetest: %s with no reach or no write reach changed %d rows (%v)", role, tag.RowsAffected(), err)
						}
					}
				}
				_ = tx.Rollback(p.ctx)
			}
		}
	}
	// The fence on the access: no SQL on the reader's connection may assume a
	// role that writes.
	for _, role := range []string{p.proof.Roles.StrictWrite, p.proof.Roles.PrivilegedWrite} {
		if _, err := p.reader.Exec(p.ctx, `SELECT set_config('role', $1, true)`, role); sqlState(err) != "42501" {
			p.t.Fatalf("rowscopetest: the read-only runtime login may assume write role %s (SQLSTATE %q): SQL sent in a read transaction can write", role, sqlState(err))
		}
	}
	p.compare("an unbound transaction")
}

func (p *prover) round(round int) {
	p.t.Helper()
	binding := p.randomBinding()
	ctx := context.WithValue(p.ctx, bindingKey{}, binding)
	describe := fmt.Sprintf("round %d, %s %s as %s in %s reaching %v", round, binding.Mode, binding.Access, binding.Principal, binding.Partition, binding.Reach)
	if binding.Access == postgres.ReadWrite {
		describe += fmt.Sprintf(", writing %s in %v", writeMode(binding), writeReach(binding))
	}

	// Read: exactly the rows the model allows, on the reader login.
	var seen []string
	err := p.store.Read(ctx, func(ctx context.Context, tx postgres.ReadTx) error {
		rows, err := tx.Query(ctx, `SELECT `+p.key+`::text FROM `+p.table)
		if err != nil {
			return err
		}
		seen, err = pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return err
		}
		// The reader can spell a write; the database must refuse it.
		if round%25 == 0 {
			rows, err := tx.Query(ctx, `DELETE FROM `+p.table+` RETURNING `+p.key+`::text`)
			if err == nil {
				_, err = pgx.CollectRows(rows, pgx.RowTo[string])
			}
			if sqlState(err) != "25006" {
				return fmt.Errorf("a read transaction ran a DELETE (SQLSTATE %q)", sqlState(err))
			}
			return errRollBack
		}
		return nil
	})
	if err != nil && !errors.Is(err, errRollBack) {
		p.t.Fatalf("rowscopetest: %s: read: %v", describe, err)
	}
	p.reads++
	p.same(describe+": read", seen, p.expected(binding, mayRead))

	// A Read binding never mutates: the Store gives it no writer, and the
	// database refuses what its transaction could send anyway.
	if binding.Access == postgres.Read {
		err := p.store.Write(ctx, func(context.Context, postgres.WriteTx) error {
			p.t.Fatalf("rowscopetest: %s: a Read binding opened a write transaction", describe)
			return nil
		})
		if !errors.Is(err, postgres.ErrReadOnly) {
			p.t.Fatalf("rowscopetest: %s: write on a Read binding: %v, want ErrReadOnly", describe, err)
		}
		p.attack(binding, describe)
		if round%10 == 9 {
			p.compare(describe)
		}
		return
	}

	// Write: one action per round, aimed as often at what is not the caller's.
	switch p.random.IntN(7) {
	case 0: // rewrite every row in sight
		body := fmt.Sprintf("round-%d", round)
		touched := p.write(ctx, describe, `UPDATE `+p.table+` SET `+p.body+` = $1 RETURNING `+p.key+`::text`, body)
		p.same(describe+": update", touched, p.expected(binding, mayWrite))
		for _, key := range touched {
			changed := p.model[key]
			changed.body = body
			p.model[key] = changed
		}
	case 1: // delete named rows, whoever's they are: one per kind of miss
		for _, key := range p.targets(binding) {
			target := p.model[key]
			touched := p.write(ctx, describe, `DELETE FROM `+p.table+` WHERE `+p.key+`::text = $1 RETURNING `+p.key+`::text`, key)
			if mayWrite(binding, target) {
				p.same(describe+": delete of a row it may write", touched, []string{key})
				delete(p.model, key)
			} else {
				p.same(describe+": delete of a row it may not write", touched, nil)
			}
		}
	case 2: // rewrite named rows, whoever's they are: one per kind of miss
		body := fmt.Sprintf("round-%d", round)
		for _, key := range p.targets(binding) {
			target := p.model[key]
			touched := p.write(ctx, describe, `UPDATE `+p.table+` SET `+p.body+` = $1 WHERE `+p.key+`::text = $2 RETURNING `+p.key+`::text`, body, key)
			if mayWrite(binding, target) {
				p.same(describe+": update of a row it may write", touched, []string{key})
				target.body = body
				p.model[key] = target
			} else {
				p.same(describe+": update of a row it may not write", touched, nil)
			}
		}
	case 3, 4: // insert: the caller's own row where it may write, then each row one step away from it
		reach := writeReach(binding)
		own := row{
			partition: binding.Partition, scope: reach[p.random.IntN(len(reach))], principal: binding.Principal,
			shared: p.random.IntN(4) == 0, body: fmt.Sprintf("round-%d", round),
		}
		candidates := []row{own}
		step := func(edit func(*row)) {
			candidate := own
			edit(&candidate)
			candidates = append(candidates, candidate)
		}
		// Another principal's, where the caller may otherwise write.
		step(func(candidate *row) { candidate.principal = p.pick(p.principals) })
		// Its own, in a scope it reads and may not write, or any scope at all.
		step(func(candidate *row) {
			candidate.scope = p.pick(p.scopes)
			for _, scope := range binding.Reach {
				if !slices.Contains(reach, scope) {
					candidate.scope = scope
				}
			}
		})
		// Its own, in another partition.
		step(func(candidate *row) { candidate.partition = p.pick(p.partitions) })
		// Anything at all.
		step(func(candidate *row) {
			shared, body := candidate.shared, candidate.body
			*candidate = p.randomRow()
			candidate.shared, candidate.body = shared, body
		})
		statement, extra := p.insertSQL()
		for _, candidate := range candidates {
			var key string
			err := p.store.Write(ctx, func(ctx context.Context, tx postgres.WriteTx) error {
				return tx.QueryRow(ctx, statement, p.insertArguments(candidate, extra)...).Scan(&key)
			})
			switch {
			case mayWrite(binding, candidate) && err != nil:
				p.t.Fatalf("rowscopetest: %s: insert of %+v it may write was refused: %v", describe, candidate, err)
			case mayWrite(binding, candidate):
				p.model[key] = candidate
				p.accepted++
			case sqlState(err) != "42501":
				p.t.Fatalf("rowscopetest: %s: insert of %+v it may not write: %v, want a row-policy refusal", describe, candidate, err)
			default:
				p.refused++
			}
		}
	case 5: // move every row in sight to another scope, principal or partition
		// Even to a value the binding itself holds: these columns never change.
		for _, move := range []struct{ column, value string }{
			{p.scope, writeReach(binding)[0]}, {p.principal, binding.Principal}, {p.partition, binding.Partition},
		} {
			err := p.store.Write(ctx, func(ctx context.Context, tx postgres.WriteTx) error {
				_, err := tx.Exec(ctx, `UPDATE `+p.table+` SET `+move.column+` = $1`, move.value)
				return err
			})
			if sqlState(err) != "42501" {
				p.t.Fatalf("rowscopetest: %s: UPDATE of %s: %v, want permission denied", describe, move.column, err)
			}
			p.refused++
		}
	case 6: // read inside the write transaction: the reach, as the write mode
		var seen []string
		if err := p.store.Write(ctx, func(ctx context.Context, tx postgres.WriteTx) error {
			rows, err := tx.Query(ctx, `SELECT `+p.key+`::text FROM `+p.table)
			if err != nil {
				return err
			}
			seen, err = pgx.CollectRows(rows, pgx.RowTo[string])
			return err
		}); err != nil {
			p.t.Fatalf("rowscopetest: %s: read inside a write transaction: %v", describe, err)
		}
		p.reads++
		p.same(describe+": read inside a write transaction", seen, p.expected(binding, seesInWrite))
	}
	// What the database now holds is what the model says, whatever the
	// transaction reported about itself.
	if round%10 == 9 {
		p.compare(describe)
	}
}

var errRollBack = errors.New("roll back")

// attack sends, as the reader's login in a READ WRITE transaction bound to the
// Read binding's own role, the writes its transaction could be made to send.
// Every setting is bound as a writer's would be, the write reach included, so
// that nothing stands in the way but what the role holds: each must be
// permission denied, not a silent zero.
func (p *prover) attack(binding postgres.Binding, describe string) {
	p.t.Helper()
	role := p.proof.Roles.StrictRead
	if binding.Mode == postgres.Privileged {
		role = p.proof.Roles.PrivilegedRead
	}
	settings := p.proof.Settings
	reach := strings.Join(binding.Reach, ",")
	tx, err := p.reader.BeginTx(p.ctx, pgx.TxOptions{AccessMode: pgx.ReadWrite})
	if err != nil {
		p.t.Fatalf("rowscopetest: %v", err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(p.ctx, `SELECT set_config($1, $2, true), set_config($3, $4, true), set_config($5, $6, true), set_config($7, $8, true), set_config('role', $9, true)`,
		settings.Partition, binding.Partition, settings.Principal, binding.Principal, settings.Reach, reach, settings.WriteReach, reach, role); err != nil {
		p.t.Fatalf("rowscopetest: %s: assume %s on the read-only login: %v", describe, role, err)
	}
	insert, extra := p.insertSQL()
	own := row{partition: binding.Partition, scope: binding.Reach[0], principal: binding.Principal, body: "attack"}
	for _, attempt := range []struct {
		statement string
		arguments []any
	}{
		{`DELETE FROM ` + p.table, nil},
		{`UPDATE ` + p.table + ` SET ` + p.body + ` = 'attack'`, nil},
		{insert, p.insertArguments(own, extra)},
		{`SELECT 1 FROM ` + p.table + ` FOR UPDATE`, nil},
		{`TRUNCATE ` + p.table, nil},
	} {
		savepoint, err := tx.Begin(p.ctx)
		if err != nil {
			p.t.Fatalf("rowscopetest: %v", err)
		}
		_, err = savepoint.Exec(p.ctx, attempt.statement, attempt.arguments...)
		_ = savepoint.Rollback(p.ctx)
		if sqlState(err) != "42501" {
			p.t.Fatalf("rowscopetest: %s: on read role %s outside READ ONLY, %s => %v (SQLSTATE %q), want permission denied: the role holds more than SELECT (seed %d)",
				describe, role, attempt.statement, err, sqlState(err), p.proof.Seed)
		}
		p.denied++
	}
	p.readers++
}

// targets picks the rows a write is aimed at. Aiming at random would almost
// always miss by the partition alone, and prove only the wall; so there is one
// row of each kind of nearest miss that exists — a row the write transaction
// sees and may not write because it is another principal's, one it sees in a
// scope outside its write reach, one its reads return and its write
// transaction does not — and then a row of the binding's partition, or any row.
func (p *prover) targets(binding postgres.Binding) []string {
	var byPrincipal, byReach, byMode, local, all []string
	keys := p.keys()
	sort.Strings(keys)
	for _, key := range keys {
		candidate := p.model[key]
		all = append(all, key)
		if candidate.partition == binding.Partition {
			local = append(local, key)
		}
		switch inWriteReach := slices.Contains(writeReach(binding), candidate.scope); {
		case mayWrite(binding, candidate):
		case seesInWrite(binding, candidate) && inWriteReach:
			byPrincipal = append(byPrincipal, key)
		case seesInWrite(binding, candidate):
			byReach = append(byReach, key)
		case mayRead(binding, candidate):
			byMode = append(byMode, key)
		}
	}
	any := all
	if len(local) > 0 && p.random.IntN(2) == 0 {
		any = local
	}
	var picked []string
	for _, from := range [][]string{byPrincipal, byReach, byMode, any} {
		if len(from) == 0 {
			continue
		}
		if key := p.pick(from); !slices.Contains(picked, key) {
			picked = append(picked, key)
		}
	}
	return picked
}

func (p *prover) write(ctx context.Context, describe, statement string, arguments ...any) []string {
	p.t.Helper()
	var touched []string
	err := p.store.Write(ctx, func(ctx context.Context, tx postgres.WriteTx) error {
		rows, err := tx.Query(ctx, statement, arguments...)
		if err != nil {
			return err
		}
		touched, err = pgx.CollectRows(rows, pgx.RowTo[string])
		return err
	})
	if err != nil {
		p.t.Fatalf("rowscopetest: %s: %s: %v", describe, statement, err)
	}
	if len(touched) > 0 {
		p.accepted++
	} else {
		p.refused++
	}
	return touched
}

func (p *prover) same(what string, got, want []string) {
	p.t.Helper()
	got = slices.Clone(got)
	sort.Strings(got)
	if slices.Equal(got, want) {
		return
	}
	var extra, missing []string
	for _, key := range got {
		if !slices.Contains(want, key) {
			extra = append(extra, fmt.Sprintf("%s %+v", key, p.model[key]))
		}
	}
	for _, key := range want {
		if !slices.Contains(got, key) {
			missing = append(missing, fmt.Sprintf("%s %+v", key, p.model[key]))
		}
	}
	p.t.Fatalf("rowscopetest: %s (seed %d)\n  reached and must not: %v\n  must reach and did not: %v", what, p.proof.Seed, extra, missing)
}

// compare reads every row of the proof's partitions through the fixture
// principal and requires the model, row for row.
func (p *prover) compare(after string) {
	p.t.Helper()
	rows, err := p.fixture.Query(p.ctx, `SELECT `+p.key+`::text, `+p.partition+`, `+p.scope+`, `+p.principal+`, `+p.shared+`, `+p.body+`
		FROM `+p.table+` WHERE `+p.partition+` = ANY($1) OR `+p.key+`::text = ANY($2)`, p.partitions, p.keys())
	if err != nil {
		p.t.Fatalf("rowscopetest: inspect through the fixture principal: %v", err)
	}
	stored := map[string]row{}
	var key string
	var found row
	if _, err := pgx.ForEachRow(rows, []any{&key, &found.partition, &found.scope, &found.principal, &found.shared, &found.body}, func() error {
		stored[key] = found
		return nil
	}); err != nil {
		p.t.Fatalf("rowscopetest: inspect through the fixture principal: %v", err)
	}
	for key, want := range p.model {
		if got, ok := stored[key]; !ok || got != want {
			p.t.Fatalf("rowscopetest: after %s (seed %d): row %s is %+v (present %v), the model has %+v", after, p.proof.Seed, key, got, ok, want)
		}
	}
	for key, got := range stored {
		if _, ok := p.model[key]; !ok {
			p.t.Fatalf("rowscopetest: after %s (seed %d): the table holds row %s %+v the model never wrote", after, p.proof.Seed, key, got)
		}
	}
}

func (p *prover) keys() []string {
	keys := make([]string, 0, len(p.model))
	for key := range p.model {
		keys = append(keys, key)
	}
	return keys
}

func sqlState(err error) string {
	var refused *pgconn.PgError
	if errors.As(err, &refused) {
		return refused.Code
	}
	return ""
}
