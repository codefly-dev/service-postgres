//! Authenticated, transaction-scoped access to a Codefly Postgres service.
//!
//! Schema ownership and cross-tenant control-plane work do not belong in this
//! library. A request-time consumer receives only a read transaction or an
//! explicitly authorized write transaction, both bound to a verified tenant and
//! principal for their complete lifetime.

use std::fmt;
use std::ops::{Deref, DerefMut};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use sqlx::postgres::{PgArguments, PgConnectOptions, PgPool, PgPoolOptions, PgQueryResult, PgRow};
use sqlx::query::{Query, QueryAs};
use sqlx::{FromRow, Postgres, Transaction};
use tokio::time::{timeout_at, Instant};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticationFailure {
    Unauthenticated,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteAuthorizationFailure {
    Unauthorized,
    Unavailable,
}

/// The minimal database identity returned by an application's verified auth
/// adapter. IDs are opaque; the SDK only validates that neither is empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    tenant_id: String,
    principal_id: String,
}

impl Principal {
    pub fn new(tenant_id: impl Into<String>, principal_id: impl Into<String>) -> Result<Self> {
        let tenant_id = tenant_id.into().trim().to_string();
        let principal_id = principal_id.into().trim().to_string();
        if tenant_id.is_empty() || principal_id.is_empty() {
            return Err(Error::Unauthenticated);
        }
        Ok(Self {
            tenant_id,
            principal_id,
        })
    }

    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    pub fn principal_id(&self) -> &str {
        &self.principal_id
    }
}

/// Application-owned adapter over an already verified request/effect context.
/// The SDK calls it for every capability issuance; repositories never receive
/// caller-supplied tenant or principal strings directly.
#[async_trait]
pub trait Authenticator: Send + Sync {
    async fn authenticated_principal(
        &self,
    ) -> std::result::Result<Principal, AuthenticationFailure>;

    async fn authorize_database_write(
        &self,
        principal: &Principal,
    ) -> std::result::Result<(), WriteAuthorizationFailure>;
}

#[derive(Debug)]
pub enum Error {
    InvalidConfiguration(&'static str),
    Unauthenticated,
    AuthenticationUnavailable,
    Unauthorized,
    AuthorizationUnavailable,
    OperationTimedOut,
    Database(sqlx::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(detail) => {
                write!(
                    formatter,
                    "invalid Postgres capability configuration: {detail}"
                )
            }
            Self::Unauthenticated => write!(formatter, "Postgres scope requires authentication"),
            Self::AuthenticationUnavailable => {
                write!(formatter, "Postgres authentication is unavailable")
            }
            Self::Unauthorized => write!(formatter, "Postgres write capability is unauthorized"),
            Self::AuthorizationUnavailable => {
                write!(formatter, "Postgres write authorization is unavailable")
            }
            Self::OperationTimedOut => write!(formatter, "Postgres operation timed out"),
            Self::Database(_) => write!(formatter, "Postgres operation failed"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            _ => None,
        }
    }
}

impl From<sqlx::Error> for Error {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

#[derive(Debug, Clone)]
pub struct FactoryOptions {
    tenant_setting: String,
    principal_setting: String,
    max_connections: u32,
    acquire_timeout: Duration,
    operation_timeout: Duration,
}

impl Default for FactoryOptions {
    fn default() -> Self {
        Self {
            tenant_setting: "codefly.current_tenant_id".to_string(),
            principal_setting: "codefly.current_principal_id".to_string(),
            max_connections: 5,
            acquire_timeout: Duration::from_secs(5),
            operation_timeout: Duration::from_secs(5),
        }
    }
}

impl FactoryOptions {
    pub fn with_scope_settings(
        mut self,
        tenant_setting: impl Into<String>,
        principal_setting: impl Into<String>,
    ) -> Result<Self> {
        let tenant_setting = tenant_setting.into();
        let principal_setting = principal_setting.into();
        validate_setting_name(&tenant_setting)?;
        validate_setting_name(&principal_setting)?;
        if tenant_setting == principal_setting {
            return Err(Error::InvalidConfiguration(
                "tenant and principal settings must be distinct",
            ));
        }
        self.tenant_setting = tenant_setting;
        self.principal_setting = principal_setting;
        Ok(self)
    }

    pub fn with_max_connections(mut self, max_connections: u32) -> Result<Self> {
        if max_connections == 0 {
            return Err(Error::InvalidConfiguration(
                "max connections must be positive",
            ));
        }
        self.max_connections = max_connections;
        Ok(self)
    }

    pub fn with_acquire_timeout(mut self, timeout: Duration) -> Result<Self> {
        if timeout.is_zero() {
            return Err(Error::InvalidConfiguration(
                "acquire timeout must be positive",
            ));
        }
        self.acquire_timeout = timeout;
        Ok(self)
    }

    pub fn with_operation_timeout(mut self, timeout: Duration) -> Result<Self> {
        if timeout.is_zero() {
            return Err(Error::InvalidConfiguration(
                "operation timeout must be positive",
            ));
        }
        self.operation_timeout = timeout;
        Ok(self)
    }

    fn validate(&self) -> Result<()> {
        validate_setting_name(&self.tenant_setting)?;
        validate_setting_name(&self.principal_setting)?;
        if self.tenant_setting == self.principal_setting
            || self.max_connections == 0
            || self.acquire_timeout.is_zero()
            || self.operation_timeout.is_zero()
        {
            return Err(Error::InvalidConfiguration("invalid factory options"));
        }
        Ok(())
    }
}

/// Owns the private reader/writer pools and mints scoped transaction
/// capabilities through an application Authenticator.
#[derive(Clone)]
pub struct Factory {
    reader: PgPool,
    writer: PgPool,
    options: Arc<FactoryOptions>,
}

impl fmt::Debug for Factory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Factory")
            .field("tenant_setting", &self.options.tenant_setting)
            .field("principal_setting", &self.options.principal_setting)
            .field("max_connections", &self.options.max_connections)
            .finish_non_exhaustive()
    }
}

impl Factory {
    /// Construct lazy pools from Codefly's distinct runtime capabilities.
    /// Connection values are never retained in errors or Debug output.
    pub fn connect_lazy(
        read_only_connection: &str,
        read_write_connection: &str,
        options: FactoryOptions,
    ) -> Result<Self> {
        options.validate()?;
        let reader_options = parse_connection(read_only_connection)?;
        let writer_options = parse_connection(read_write_connection)?;
        if reader_options.get_username().trim().is_empty()
            || writer_options.get_username().trim().is_empty()
            || reader_options.get_username() == writer_options.get_username()
        {
            return Err(Error::InvalidConfiguration(
                "read-only and read-write capabilities must use distinct database roles",
            ));
        }
        let reader = PgPoolOptions::new()
            .max_connections(options.max_connections)
            .acquire_timeout(options.acquire_timeout)
            .connect_lazy_with(reader_options);
        let writer = PgPoolOptions::new()
            .max_connections(options.max_connections)
            .acquire_timeout(options.acquire_timeout)
            .connect_lazy_with(writer_options);
        Ok(Self {
            reader,
            writer,
            options: Arc::new(options),
        })
    }

    pub async fn reader(&self, authenticator: &dyn Authenticator) -> Result<ReadTransaction> {
        let principal = resolve_principal(authenticator).await?;
        self.begin(&self.reader, "BEGIN READ ONLY", principal).await
    }

    pub async fn writer(&self, authenticator: &dyn Authenticator) -> Result<WriteTransaction> {
        let principal = resolve_principal(authenticator).await?;
        authenticator
            .authorize_database_write(&principal)
            .await
            .map_err(|failure| match failure {
                WriteAuthorizationFailure::Unauthorized => Error::Unauthorized,
                WriteAuthorizationFailure::Unavailable => Error::AuthorizationUnavailable,
            })?;
        self.begin(&self.writer, "BEGIN READ WRITE", principal)
            .await
            .map(|read| WriteTransaction { read })
    }

    async fn begin(
        &self,
        pool: &PgPool,
        statement: &'static str,
        principal: Principal,
    ) -> Result<ReadTransaction> {
        let deadline = Instant::now() + self.options.operation_timeout;
        let transaction = timeout_at(deadline, pool.begin_with(statement))
            .await
            .map_err(|_| Error::OperationTimedOut)??;
        let mut transaction = ReadTransaction {
            transaction: Some(transaction),
            deadline,
            tenant_setting: self.options.tenant_setting.clone(),
        };
        let timeout_ms = self
            .options
            .operation_timeout
            .as_millis()
            .max(1)
            .to_string();
        transaction
            .execute_internal(
                sqlx::query(
                    "SELECT set_config($1, $2, true), set_config($3, $4, true), \
                            set_config('statement_timeout', $5, true), \
                            set_config('idle_in_transaction_session_timeout', $5, true)",
                )
                .bind(&self.options.tenant_setting)
                .bind(principal.tenant_id())
                .bind(&self.options.principal_setting)
                .bind(principal.principal_id())
                .bind(timeout_ms),
            )
            .await?;
        Ok(transaction)
    }
}

async fn resolve_principal(authenticator: &dyn Authenticator) -> Result<Principal> {
    authenticator
        .authenticated_principal()
        .await
        .map_err(|failure| match failure {
            AuthenticationFailure::Unauthenticated => Error::Unauthenticated,
            AuthenticationFailure::Unavailable => Error::AuthenticationUnavailable,
        })
}

/// Query-only transaction capability. It intentionally has no general executor
/// or mutation method, so application repositories cannot accidentally write
/// through a reader even before the database's read-only role rejects it.
pub struct ReadTransaction {
    transaction: Option<Transaction<'static, Postgres>>,
    deadline: Instant,
    tenant_setting: String,
}

impl fmt::Debug for ReadTransaction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReadTransaction")
            .finish_non_exhaustive()
    }
}

impl ReadTransaction {
    pub async fn fetch_all<'q>(
        &mut self,
        query: Query<'q, Postgres, PgArguments>,
    ) -> Result<Vec<PgRow>> {
        let deadline = self.deadline;
        let transaction = self.transaction_mut()?;
        bounded(deadline, query.fetch_all(&mut **transaction)).await
    }

    pub async fn fetch_one<'q>(
        &mut self,
        query: Query<'q, Postgres, PgArguments>,
    ) -> Result<PgRow> {
        let deadline = self.deadline;
        let transaction = self.transaction_mut()?;
        bounded(deadline, query.fetch_one(&mut **transaction)).await
    }

    pub async fn fetch_optional<'q>(
        &mut self,
        query: Query<'q, Postgres, PgArguments>,
    ) -> Result<Option<PgRow>> {
        let deadline = self.deadline;
        let transaction = self.transaction_mut()?;
        bounded(deadline, query.fetch_optional(&mut **transaction)).await
    }

    pub async fn fetch_all_as<'q, O>(
        &mut self,
        query: QueryAs<'q, Postgres, O, PgArguments>,
    ) -> Result<Vec<O>>
    where
        O: Send + Unpin + for<'row> FromRow<'row, PgRow>,
    {
        let deadline = self.deadline;
        let transaction = self.transaction_mut()?;
        bounded(deadline, query.fetch_all(&mut **transaction)).await
    }

    pub async fn fetch_one_as<'q, O>(
        &mut self,
        query: QueryAs<'q, Postgres, O, PgArguments>,
    ) -> Result<O>
    where
        O: Send + Unpin + for<'row> FromRow<'row, PgRow>,
    {
        let deadline = self.deadline;
        let transaction = self.transaction_mut()?;
        bounded(deadline, query.fetch_one(&mut **transaction)).await
    }

    pub async fn fetch_optional_as<'q, O>(
        &mut self,
        query: QueryAs<'q, Postgres, O, PgArguments>,
    ) -> Result<Option<O>>
    where
        O: Send + Unpin + for<'row> FromRow<'row, PgRow>,
    {
        let deadline = self.deadline;
        let transaction = self.transaction_mut()?;
        bounded(deadline, query.fetch_optional(&mut **transaction)).await
    }

    pub async fn commit(mut self) -> Result<()> {
        let transaction = self.transaction.take().ok_or(Error::InvalidConfiguration(
            "transaction is already complete",
        ))?;
        bounded(self.deadline, transaction.commit()).await
    }

    async fn execute_internal<'q>(
        &mut self,
        query: Query<'q, Postgres, PgArguments>,
    ) -> Result<PgQueryResult> {
        let deadline = self.deadline;
        let transaction = self.transaction_mut()?;
        bounded(deadline, query.execute(&mut **transaction)).await
    }

    fn transaction_mut(&mut self) -> Result<&mut Transaction<'static, Postgres>> {
        self.transaction.as_mut().ok_or(Error::InvalidConfiguration(
            "transaction is already complete",
        ))
    }
}

/// Authorized mutation capability. It dereferences to the query-only surface
/// for invariant checks and adds only explicit mutation operations.
pub struct WriteTransaction {
    read: ReadTransaction,
}

impl fmt::Debug for WriteTransaction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WriteTransaction")
            .finish_non_exhaustive()
    }
}

impl Deref for WriteTransaction {
    type Target = ReadTransaction;

    fn deref(&self) -> &Self::Target {
        &self.read
    }
}

impl DerefMut for WriteTransaction {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.read
    }
}

impl WriteTransaction {
    pub async fn execute<'q>(
        &mut self,
        query: Query<'q, Postgres, PgArguments>,
    ) -> Result<PgQueryResult> {
        self.read.execute_internal(query).await
    }

    /// Serialize a logical resource inside the authenticated tenant. The
    /// transaction scope supplies the tenant; repository code supplies only a
    /// namespace and opaque resource components.
    pub async fn scoped_advisory_lock(
        &mut self,
        namespace: &str,
        components: &[&str],
    ) -> Result<()> {
        let namespace = namespace.trim();
        if namespace.is_empty() {
            return Err(Error::InvalidConfiguration(
                "advisory-lock namespace is required",
            ));
        }
        let components = serde_json::to_string(components).map_err(|_| {
            Error::InvalidConfiguration("advisory-lock components could not be encoded")
        })?;
        let tenant_setting = self.read.tenant_setting.clone();
        self.execute(
            sqlx::query(
                "SELECT pg_advisory_xact_lock(hashtextextended(\
                    jsonb_build_array(\
                        NULLIF(current_setting($1, true), ''),\
                        $2::text,\
                        $3::jsonb\
                    )::text,\
                    0\
                ))",
            )
            .bind(tenant_setting)
            .bind(namespace)
            .bind(components),
        )
        .await?;
        Ok(())
    }

    pub async fn commit(self) -> Result<()> {
        self.read.commit().await
    }
}

async fn bounded<F, T>(deadline: Instant, future: F) -> Result<T>
where
    F: std::future::Future<Output = std::result::Result<T, sqlx::Error>>,
{
    timeout_at(deadline, future)
        .await
        .map_err(|_| Error::OperationTimedOut)?
        .map_err(Error::Database)
}

fn parse_connection(connection: &str) -> Result<PgConnectOptions> {
    if connection.trim().is_empty() {
        return Err(Error::InvalidConfiguration(
            "database connection capability is required",
        ));
    }
    PgConnectOptions::from_str(connection)
        .map_err(|_| Error::InvalidConfiguration("database connection capability is invalid"))
}

fn validate_setting_name(setting: &str) -> Result<()> {
    let mut segments = setting.split('.');
    let first = segments.next().unwrap_or_default();
    let remaining: Vec<_> = segments.collect();
    if first.is_empty()
        || remaining.is_empty()
        || remaining.iter().any(|segment| segment.is_empty())
    {
        return Err(Error::InvalidConfiguration(
            "scope setting must contain a non-empty namespace",
        ));
    }
    if setting.chars().any(|character| {
        !(character == '.' || character == '_' || character.is_ascii_alphanumeric())
    }) {
        return Err(Error::InvalidConfiguration(
            "scope setting contains an unsafe character",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn principal_requires_both_scope_dimensions() {
        assert_eq!(
            Principal::new("tenant", " principal ")
                .unwrap()
                .principal_id(),
            "principal"
        );
        assert!(matches!(
            Principal::new("", "principal"),
            Err(Error::Unauthenticated)
        ));
        assert!(matches!(
            Principal::new("tenant", " "),
            Err(Error::Unauthenticated)
        ));
    }

    #[test]
    fn scope_settings_are_validated_and_distinct() {
        assert!(FactoryOptions::default()
            .with_scope_settings("warden.tenant_id", "warden.principal_id")
            .is_ok());
        assert!(FactoryOptions::default()
            .with_scope_settings("unsafe", "warden.principal_id")
            .is_err());
        assert!(FactoryOptions::default()
            .with_scope_settings("warden.same", "warden.same")
            .is_err());
        assert!(FactoryOptions::default()
            .with_scope_settings("warden.tenant;drop", "warden.principal")
            .is_err());
    }

    #[tokio::test]
    async fn lazy_factory_requires_distinct_database_roles() {
        let same = Factory::connect_lazy(
            "postgres://same:reader@localhost/db",
            "postgres://same:writer@localhost/db",
            FactoryOptions::default(),
        );
        assert!(matches!(same, Err(Error::InvalidConfiguration(_))));

        let distinct = Factory::connect_lazy(
            "postgres://reader:secret@localhost/db",
            "postgres://writer:secret@localhost/db",
            FactoryOptions::default(),
        );
        assert!(distinct.is_ok());
        assert!(!format!("{:?}", distinct.unwrap()).contains("secret"));
    }

    #[test]
    fn errors_do_not_echo_connection_values_or_database_details() {
        let invalid = Factory::connect_lazy(
            "definitely-not-a-url-with-secret",
            "postgres://writer:other-secret@localhost/db",
            FactoryOptions::default(),
        )
        .unwrap_err();
        let rendered = invalid.to_string();
        assert!(!rendered.contains("secret"));
        assert!(!rendered.contains("definitely"));
    }
}
