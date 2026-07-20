package main

import (
	"context"
	"database/sql"
	"errors"

	scoped "github.com/codefly-dev/service-postgres/libs/go"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lib/pq"
)

// postgresCapabilityProbe keeps protocol details out of lifecycle tests. The
// tests describe externally visible database behavior; this adapter is the
// only place that translates those behaviors into Postgres operations.
type postgresCapabilityProbe struct {
	db *sql.DB
}

func openPostgresCapabilityProbe(ctx context.Context, connection string) (*postgresCapabilityProbe, error) {
	db, err := sql.Open("postgres", connection)
	if err != nil {
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return &postgresCapabilityProbe{db: db}, nil
}

func (p *postgresCapabilityProbe) Close() error {
	return p.db.Close()
}

func (p *postgresCapabilityProbe) AppendFixture(ctx context.Context, relation, id string) error {
	_, err := p.db.ExecContext(ctx, `INSERT INTO `+pq.QuoteIdentifier(relation)+` (id) VALUES ($1)`, id)
	return err
}

func (p *postgresCapabilityProbe) AppendTenantFixture(ctx context.Context, relation, id, payload string) error {
	_, err := p.db.ExecContext(ctx, `INSERT INTO `+pq.QuoteIdentifier(relation)+` (id, payload) VALUES ($1, $2)`, id, payload)
	return err
}

func (p *postgresCapabilityProbe) HasFixture(ctx context.Context, relation, id string) (bool, error) {
	var exists bool
	err := p.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM `+pq.QuoteIdentifier(relation)+` WHERE id = $1)`, id).Scan(&exists)
	return exists, err
}

func (p *postgresCapabilityProbe) RelationExists(ctx context.Context, relation string) (bool, error) {
	var exists bool
	err := p.db.QueryRowContext(ctx, `SELECT to_regclass($1) IS NOT NULL`, relation).Scan(&exists)
	return exists, err
}

func (p *postgresCapabilityProbe) CreateRelation(ctx context.Context, relation string) error {
	_, err := p.db.ExecContext(ctx, `CREATE TABLE `+pq.QuoteIdentifier(relation)+` (id UUID PRIMARY KEY)`)
	return err
}

func (p *postgresCapabilityProbe) CreateLoginRole(ctx context.Context, role string) error {
	_, err := p.db.ExecContext(ctx, `CREATE ROLE `+pq.QuoteIdentifier(role)+` LOGIN`)
	return err
}

func (p *postgresCapabilityProbe) AssumeRole(ctx context.Context, role string) error {
	_, err := p.db.ExecContext(ctx, `SET ROLE `+pq.QuoteIdentifier(role))
	return err
}

func (p *postgresCapabilityProbe) InstallTenantFixture(ctx context.Context, relation string) error {
	quotedRelation := pq.QuoteIdentifier(relation)
	statements := []string{
		`CREATE TABLE ` + quotedRelation + ` (` +
			`tenant_id TEXT NOT NULL DEFAULT current_setting('codefly.current_tenant_id', true), ` +
			`id TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY (tenant_id, id))`,
		`ALTER TABLE ` + quotedRelation + ` ENABLE ROW LEVEL SECURITY`,
		`ALTER TABLE ` + quotedRelation + ` FORCE ROW LEVEL SECURITY`,
		`CREATE POLICY ` + pq.QuoteIdentifier(relation+"_tenant") + ` ON ` + quotedRelation +
			` USING (tenant_id = current_setting('codefly.current_tenant_id', true))` +
			` WITH CHECK (tenant_id = current_setting('codefly.current_tenant_id', true))`,
	}
	for _, statement := range statements {
		if _, err := p.db.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}

type scopedFixtureRepository struct {
	factory  *scoped.Factory
	relation string
}

func newScopedFixtureRepository(ctx context.Context, readerConnection, writerConnection, relation string, authenticator scoped.Authenticator) (*scopedFixtureRepository, func(), error) {
	readerPool, err := pgxpool.New(ctx, readerConnection)
	if err != nil {
		return nil, nil, err
	}
	writerPool, err := pgxpool.New(ctx, writerConnection)
	if err != nil {
		readerPool.Close()
		return nil, nil, err
	}
	factory, err := scoped.NewFactory(readerPool, writerPool, authenticator)
	if err != nil {
		readerPool.Close()
		writerPool.Close()
		return nil, nil, err
	}
	closePools := func() {
		readerPool.Close()
		writerPool.Close()
	}
	return &scopedFixtureRepository{factory: factory, relation: relation}, closePools, nil
}

func (r *scopedFixtureRepository) Put(ctx context.Context, id, payload string) error {
	writer, err := r.factory.Writer(ctx)
	if err != nil {
		return err
	}
	return writer.InTransaction(ctx, func(ctx context.Context, tx scoped.WriteTx) error {
		_, err := tx.Exec(ctx, `INSERT INTO `+pq.QuoteIdentifier(r.relation)+` (id, payload) VALUES ($1, $2)`, id, payload)
		return err
	})
}

func (r *scopedFixtureRepository) Get(ctx context.Context, id string) (string, bool, error) {
	reader, err := r.factory.Reader(ctx)
	if err != nil {
		return "", false, err
	}
	var payload string
	err = reader.InTransaction(ctx, func(ctx context.Context, tx scoped.ReadTx) error {
		return tx.QueryRow(ctx, `SELECT payload FROM `+pq.QuoteIdentifier(r.relation)+` WHERE id = $1`, id).Scan(&payload)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	return payload, err == nil, err
}

type databasePrincipalContextKey struct{}

type databasePrincipal struct {
	tenant string
	user   string
}

func (p databasePrincipal) DatabaseTenantID() string { return p.tenant }
func (p databasePrincipal) DatabaseUserID() string   { return p.user }

func contextWithDatabasePrincipal(ctx context.Context, tenant, user string) context.Context {
	return context.WithValue(ctx, databasePrincipalContextKey{}, databasePrincipal{tenant: tenant, user: user})
}

type contextAuthenticator struct{}

func (contextAuthenticator) AuthenticatedPrincipal(ctx context.Context) (scoped.Principal, error) {
	principal, ok := ctx.Value(databasePrincipalContextKey{}).(databasePrincipal)
	if !ok {
		return nil, scoped.ErrUnauthenticated
	}
	return principal, nil
}

func (contextAuthenticator) AuthorizeDatabaseWrite(context.Context, scoped.Principal) error {
	return nil
}
