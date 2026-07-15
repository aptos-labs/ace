// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock},
};

use anyhow::{anyhow, Result};
use postgres::{Client, NoTls};
use rusqlite::{params, Connection, OptionalExtension};

use vss_common::session::{BcsPcsOpening, BcsSession, STATE_SUCCESS};
use vss_common::vss_types::pedersen_verify_private_share;
use vss_common::{normalize_account_addr, AptosRpc};

/// Dealer-side persistent state for one VSS session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DealerStateRecord {
    pub epoch: u64,
    pub session_addr: String,
    pub state_bytes: Vec<u8>,
}

/// Holder-side received share/opening for one VSS session.
///
/// `holder_index` is the zero-based index into the on-chain holder vector.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HolderShareRecord {
    pub epoch: u64,
    pub session_addr: String,
    pub holder_index: u64,
    pub share_bcs: Vec<u8>,
}

pub trait VssStore: Send + Sync {
    fn put_dealer_state(&self, record: DealerStateRecord) -> Result<()>;
    fn get_dealer_state(&self, session_addr: &str) -> Result<Option<DealerStateRecord>>;

    fn put_holder_share(&self, record: HolderShareRecord) -> Result<()>;
    fn get_holder_share(
        &self,
        session_addr: &str,
        holder_index: u64,
    ) -> Result<Option<HolderShareRecord>>;

    /// Called at epoch `x` start. Deletes epoch `x - 2` and older data.
    fn prune_at_epoch_start(&self, current_epoch: u64) -> Result<()>;

    /// Deletes rows for VSS sessions outside the supplied live session set.
    fn prune_except_sessions(&self, keep_session_addrs: &[String]) -> Result<usize>;
}

/// Resolve and verify the holder opening for one completed VSS session.
///
/// Chain-revealed openings from DC1 are authoritative and are written back to
/// the store. The local store is only a fallback for holders that ACKed and
/// therefore were not revealed in DC1.
pub async fn read_verified_holder_opening(
    rpc: &AptosRpc,
    ace: &str,
    store: &dyn VssStore,
    session_addr: &str,
    holder_index: u64,
) -> Result<BcsPcsOpening> {
    let session_addr = normalize_session_addr(session_addr);
    let bcs_session = rpc
        .get_session_bcs_decoded(ace, &session_addr)
        .await
        .map_err(|e| anyhow!("fetch VSS session {}: {}", session_addr, e))?;
    let expected_position = holder_index
        .checked_add(1)
        .ok_or_else(|| anyhow!("holder_index overflow for VSS {}", session_addr))?;
    let holder_usize = usize::try_from(holder_index)
        .map_err(|_| anyhow!("holder_index {} does not fit usize", holder_index))?;
    if holder_usize >= bcs_session.share_holders.len() {
        return Err(anyhow!(
            "holder_index {} out of range for VSS {} with {} holders",
            holder_index,
            session_addr,
            bcs_session.share_holders.len()
        ));
    }
    if bcs_session.state_code != STATE_SUCCESS {
        return Err(anyhow!(
            "VSS {} is not completed (state_code={})",
            session_addr,
            bcs_session.state_code
        ));
    }

    if let Some(opening) = revealed_opening(&bcs_session, expected_position)? {
        verify_opening_bcs(opening, &bcs_session, expected_position).map_err(|e| {
            anyhow!(
                "verify chain-revealed opening for VSS {}: {}",
                session_addr,
                e
            )
        })?;
        return Ok(opening.clone());
    }

    let record = store
        .get_holder_share(&session_addr, holder_index)?
        .ok_or_else(|| {
            anyhow!(
                "missing holder opening in chain reveal and VSS store: session={} holder_index={}",
                session_addr,
                holder_index
            )
        })?;
    pedersen_verify_private_share(
        &record.share_bcs,
        &bcs_session.pcs_context,
        &bcs_session
            .dealer_contribution_0
            .as_ref()
            .ok_or_else(|| anyhow!("VSS {} missing dealer_contribution_0", session_addr))?
            .pcs_commitment,
        expected_position,
    )
    .map_err(|e| anyhow!("verify stored opening for VSS {}: {}", session_addr, e))
}

fn revealed_opening(
    session: &BcsSession,
    expected_position: u64,
) -> Result<Option<&BcsPcsOpening>> {
    let Some(dc1) = session.dealer_contribution_1.as_ref() else {
        return Ok(None);
    };
    let idx = usize::try_from(expected_position)
        .map_err(|_| anyhow!("opening position {} does not fit usize", expected_position))?;
    Ok(dc1
        .shares_to_reveal
        .get(idx)
        .and_then(|opening| opening.as_ref()))
}

fn verify_opening_bcs(
    opening: &BcsPcsOpening,
    session: &BcsSession,
    expected_position: u64,
) -> Result<Vec<u8>> {
    let share_bcs = bcs::to_bytes(opening).map_err(|e| anyhow!("encode opening BCS: {}", e))?;
    pedersen_verify_private_share(
        &share_bcs,
        &session.pcs_context,
        &session
            .dealer_contribution_0
            .as_ref()
            .ok_or_else(|| anyhow!("missing dealer_contribution_0"))?
            .pcs_commitment,
        expected_position,
    )?;
    Ok(share_bcs)
}

static VSS_STORE_CACHE: OnceLock<Mutex<HashMap<String, Arc<dyn VssStore>>>> = OnceLock::new();

pub fn connect_vss_store(store_url: &str) -> Result<Arc<dyn VssStore>> {
    let parsed = parse_store_url(store_url)?;
    let cache_key = store_cache_key(&parsed)?;
    let cache = VSS_STORE_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut stores = cache
        .lock()
        .map_err(|_| anyhow!("VSS store singleton cache is poisoned"))?;
    if let Some(store) = stores.get(&cache_key) {
        return Ok(store.clone());
    }
    let store = open_parsed_store(parsed)?;
    stores.insert(cache_key, store.clone());
    Ok(store)
}

enum ParsedStoreUrl {
    Sqlite(PathBuf),
    Postgres(String),
}

fn open_parsed_store(parsed: ParsedStoreUrl) -> Result<Arc<dyn VssStore>> {
    match parsed {
        ParsedStoreUrl::Sqlite(path) => Ok(Arc::new(SqliteVssStore::open(path)?)),
        ParsedStoreUrl::Postgres(url) => Ok(Arc::new(PostgresVssStore::open(url)?)),
    }
}

fn store_cache_key(parsed: &ParsedStoreUrl) -> Result<String> {
    match parsed {
        ParsedStoreUrl::Sqlite(path) => {
            let absolute = if path.is_absolute() {
                path.clone()
            } else {
                std::env::current_dir()
                    .map_err(|e| anyhow!("get cwd for sqlite VSS store key: {}", e))?
                    .join(path)
            };
            Ok(format!("sqlite://{}", absolute.display()))
        }
        ParsedStoreUrl::Postgres(url) => Ok(url.clone()),
    }
}

fn parse_store_url(store_url: &str) -> Result<ParsedStoreUrl> {
    if let Some(rest) = store_url.strip_prefix("sqlite://") {
        let path = if let Some(path) = rest.strip_prefix('/') {
            PathBuf::from(format!("/{path}"))
        } else {
            PathBuf::from(rest)
        };
        if path.as_os_str().is_empty() {
            return Err(anyhow!("sqlite store URL must include a database path"));
        }
        return Ok(ParsedStoreUrl::Sqlite(path));
    }

    if let Some(rest) = store_url.strip_prefix("sqlite:") {
        if rest.is_empty() {
            return Err(anyhow!("sqlite store URL must include a database path"));
        }
        return Ok(ParsedStoreUrl::Sqlite(PathBuf::from(rest)));
    }

    if store_url.starts_with("postgres://") || store_url.starts_with("postgresql://") {
        return Ok(ParsedStoreUrl::Postgres(store_url.to_string()));
    }

    Err(anyhow!(
        "unsupported VSS store URL scheme in {store_url:?}; implemented: sqlite:///path/to/file.db, postgres://..."
    ))
}

#[derive(Clone, Debug)]
pub struct SqliteVssStore {
    path: PathBuf,
}

impl SqliteVssStore {
    pub fn open(path: PathBuf) -> Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| anyhow!("create sqlite parent {}: {}", parent.display(), e))?;
            }
        }
        let store = Self { path };
        store.init()?;
        Ok(store)
    }

    fn conn(&self) -> Result<Connection> {
        Connection::open(&self.path)
            .map_err(|e| anyhow!("open sqlite store {}: {}", self.path.display(), e))
    }

    fn init(&self) -> Result<()> {
        let conn = self.conn()?;
        conn.execute_batch(
            r#"
            create table if not exists vss_dealer_states (
              epoch integer not null,
              session_addr text primary key,
              state_bytes blob not null
            );

            create table if not exists vss_holder_shares (
              epoch integer not null,
              session_addr text not null,
              holder_index integer not null,
              share_bcs blob not null,
              primary key (session_addr, holder_index)
            );

            "#,
        )
        .map_err(|e| anyhow!("initialize sqlite VSS schema: {}", e))
    }
}

impl VssStore for SqliteVssStore {
    fn put_dealer_state(&self, record: DealerStateRecord) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            r#"
            insert or replace into vss_dealer_states(epoch, session_addr, state_bytes)
            values (?1, ?2, ?3)
            "#,
            params![
                to_i64(record.epoch)?,
                normalize_session_addr(&record.session_addr),
                record.state_bytes
            ],
        )
        .map_err(|e| anyhow!("put dealer state: {}", e))?;
        Ok(())
    }

    fn get_dealer_state(&self, session_addr: &str) -> Result<Option<DealerStateRecord>> {
        let conn = self.conn()?;
        conn.query_row(
            r#"
            select epoch, session_addr, state_bytes
            from vss_dealer_states where session_addr = ?1
            "#,
            params![normalize_session_addr(session_addr)],
            |row| {
                Ok(DealerStateRecord {
                    epoch: from_i64(row.get(0)?),
                    session_addr: row.get(1)?,
                    state_bytes: row.get(2)?,
                })
            },
        )
        .optional()
        .map_err(|e| anyhow!("get dealer state: {}", e))
    }

    fn put_holder_share(&self, record: HolderShareRecord) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            r#"
            insert or replace into vss_holder_shares(epoch, session_addr, holder_index, share_bcs)
            values (?1, ?2, ?3, ?4)
            "#,
            params![
                to_i64(record.epoch)?,
                normalize_session_addr(&record.session_addr),
                to_i64(record.holder_index)?,
                record.share_bcs
            ],
        )
        .map_err(|e| anyhow!("put holder share: {}", e))?;
        Ok(())
    }

    fn get_holder_share(
        &self,
        session_addr: &str,
        holder_index: u64,
    ) -> Result<Option<HolderShareRecord>> {
        let conn = self.conn()?;
        conn.query_row(
            r#"
            select epoch, session_addr, holder_index, share_bcs
            from vss_holder_shares where session_addr = ?1 and holder_index = ?2
            "#,
            params![normalize_session_addr(session_addr), to_i64(holder_index)?],
            |row| {
                Ok(HolderShareRecord {
                    epoch: from_i64(row.get(0)?),
                    session_addr: row.get(1)?,
                    holder_index: from_i64(row.get(2)?),
                    share_bcs: row.get(3)?,
                })
            },
        )
        .optional()
        .map_err(|e| anyhow!("get holder share: {}", e))
    }

    fn prune_at_epoch_start(&self, current_epoch: u64) -> Result<()> {
        if current_epoch < 2 {
            return Ok(());
        }
        let cutoff = to_i64(current_epoch - 2)?;
        let conn = self.conn()?;
        for table in ["vss_dealer_states", "vss_holder_shares"] {
            conn.execute(
                &format!("delete from {table} where epoch <= ?1"),
                params![cutoff],
            )
            .map_err(|e| anyhow!("prune {table}: {}", e))?;
        }
        Ok(())
    }

    fn prune_except_sessions(&self, keep_session_addrs: &[String]) -> Result<usize> {
        let keep = normalized_session_set(keep_session_addrs);
        let conn = self.conn()?;
        let mut deleted = 0usize;
        for table in ["vss_dealer_states", "vss_holder_shares"] {
            let sessions = {
                let mut stmt = conn
                    .prepare(&format!("select distinct session_addr from {table}"))
                    .map_err(|e| anyhow!("list sessions in {table}: {}", e))?;
                let rows = stmt
                    .query_map([], |row| row.get::<_, String>(0))
                    .map_err(|e| anyhow!("list sessions in {table}: {}", e))?
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(|e| anyhow!("read sessions in {table}: {}", e))?;
                rows
            };
            for session in sessions {
                if !keep.contains(&normalize_session_addr(&session)) {
                    deleted += conn
                        .execute(
                            &format!("delete from {table} where session_addr = ?1"),
                            params![session],
                        )
                        .map_err(|e| anyhow!("prune stale sessions from {table}: {}", e))?;
                }
            }
        }
        Ok(deleted)
    }
}

#[derive(Clone, Debug)]
pub struct PostgresVssStore {
    url: String,
}

impl PostgresVssStore {
    pub fn open(url: String) -> Result<Self> {
        let store = Self { url };
        store.init()?;
        Ok(store)
    }

    fn with_client<T>(&self, f: impl FnOnce(&mut Client) -> Result<T>) -> Result<T> {
        run_sync_postgres(|| {
            let mut client = Client::connect(&self.url, NoTls)
                .map_err(|e| anyhow!("open postgres VSS store: {}", e))?;
            f(&mut client)
        })
    }

    fn init(&self) -> Result<()> {
        self.with_client(|client| {
            client
                .batch_execute(
                    r#"
                create table if not exists vss_dealer_states (
                  epoch bigint not null,
                  session_addr text primary key,
                  state_bytes bytea not null
                );

                create table if not exists vss_holder_shares (
                  epoch bigint not null,
                  session_addr text not null,
                  holder_index bigint not null,
                  share_bcs bytea not null,
                  primary key (session_addr, holder_index)
                );

                "#,
                )
                .map_err(|e| anyhow!("initialize postgres VSS schema: {}", e))?;
            Ok(())
        })
    }
}

impl VssStore for PostgresVssStore {
    fn put_dealer_state(&self, record: DealerStateRecord) -> Result<()> {
        self.with_client(|client| {
            client
                .execute(
                    r#"
                insert into vss_dealer_states(epoch, session_addr, state_bytes)
                values ($1, $2, $3)
                on conflict (session_addr) do update
                set epoch = excluded.epoch,
                    state_bytes = excluded.state_bytes
                "#,
                    &[
                        &to_i64(record.epoch)?,
                        &normalize_session_addr(&record.session_addr),
                        &record.state_bytes,
                    ],
                )
                .map_err(|e| anyhow!("put dealer state: {}", e))?;
            Ok(())
        })
    }

    fn get_dealer_state(&self, session_addr: &str) -> Result<Option<DealerStateRecord>> {
        self.with_client(|client| {
            let row = client
                .query_opt(
                    r#"
                select epoch, session_addr, state_bytes
                from vss_dealer_states where session_addr = $1
                "#,
                    &[&normalize_session_addr(session_addr)],
                )
                .map_err(|e| anyhow!("get dealer state: {}", e))?;
            Ok(row.map(|row| DealerStateRecord {
                epoch: from_i64(row.get(0)),
                session_addr: row.get(1),
                state_bytes: row.get(2),
            }))
        })
    }

    fn put_holder_share(&self, record: HolderShareRecord) -> Result<()> {
        self.with_client(|client| {
            client
                .execute(
                    r#"
                insert into vss_holder_shares(epoch, session_addr, holder_index, share_bcs)
                values ($1, $2, $3, $4)
                on conflict (session_addr, holder_index) do update
                set epoch = excluded.epoch,
                    share_bcs = excluded.share_bcs
                "#,
                    &[
                        &to_i64(record.epoch)?,
                        &normalize_session_addr(&record.session_addr),
                        &to_i64(record.holder_index)?,
                        &record.share_bcs,
                    ],
                )
                .map_err(|e| anyhow!("put holder share: {}", e))?;
            Ok(())
        })
    }

    fn get_holder_share(
        &self,
        session_addr: &str,
        holder_index: u64,
    ) -> Result<Option<HolderShareRecord>> {
        self.with_client(|client| {
            let row = client
                .query_opt(
                    r#"
                select epoch, session_addr, holder_index, share_bcs
                from vss_holder_shares where session_addr = $1 and holder_index = $2
                "#,
                    &[
                        &normalize_session_addr(session_addr),
                        &to_i64(holder_index)?,
                    ],
                )
                .map_err(|e| anyhow!("get holder share: {}", e))?;
            Ok(row.map(|row| HolderShareRecord {
                epoch: from_i64(row.get(0)),
                session_addr: row.get(1),
                holder_index: from_i64(row.get(2)),
                share_bcs: row.get(3),
            }))
        })
    }

    fn prune_at_epoch_start(&self, current_epoch: u64) -> Result<()> {
        if current_epoch < 2 {
            return Ok(());
        }
        let cutoff = to_i64(current_epoch - 2)?;
        self.with_client(|client| {
            for table in ["vss_dealer_states", "vss_holder_shares"] {
                client
                    .execute(
                        &format!("delete from {table} where epoch <= $1"),
                        &[&cutoff],
                    )
                    .map_err(|e| anyhow!("prune {table}: {}", e))?;
            }
            Ok(())
        })
    }

    fn prune_except_sessions(&self, keep_session_addrs: &[String]) -> Result<usize> {
        let keep = normalized_session_set(keep_session_addrs);
        self.with_client(|client| {
            let mut deleted = 0usize;
            for table in ["vss_dealer_states", "vss_holder_shares"] {
                let rows = client
                    .query(&format!("select distinct session_addr from {table}"), &[])
                    .map_err(|e| anyhow!("list sessions in {table}: {}", e))?;
                for row in rows {
                    let session: String = row.get(0);
                    if !keep.contains(&normalize_session_addr(&session)) {
                        deleted += client
                            .execute(
                                &format!("delete from {table} where session_addr = $1"),
                                &[&session],
                            )
                            .map_err(|e| anyhow!("prune stale sessions from {table}: {}", e))?
                            as usize;
                    }
                }
            }
            Ok(deleted)
        })
    }
}

fn run_sync_postgres<T>(f: impl FnOnce() -> Result<T>) -> Result<T> {
    if tokio::runtime::Handle::try_current().is_ok() {
        tokio::task::block_in_place(f)
    } else {
        f()
    }
}

fn normalize_session_addr(session_addr: &str) -> String {
    normalize_account_addr(session_addr)
}

fn normalized_session_set(session_addrs: &[String]) -> HashSet<String> {
    session_addrs
        .iter()
        .map(|addr| normalize_session_addr(addr))
        .collect()
}

fn to_i64(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| anyhow!("value {value} does not fit in sqlite integer"))
}

fn from_i64(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_store() -> (tempfile::TempDir, SqliteVssStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteVssStore::open(dir.path().join("vss.db")).unwrap();
        (dir, store)
    }

    #[test]
    fn sqlite_round_trips_minimal_vss_data() {
        let (_dir, store) = test_store();
        let session = "0xabc";

        let state = DealerStateRecord {
            epoch: 7,
            session_addr: session.to_string(),
            state_bytes: b"dealer-state".to_vec(),
        };
        store.put_dealer_state(state.clone()).unwrap();
        assert_eq!(
            store.get_dealer_state(session).unwrap(),
            Some(DealerStateRecord {
                session_addr: normalize_account_addr(session),
                ..state
            })
        );

        let share = HolderShareRecord {
            epoch: 7,
            session_addr: session.to_string(),
            holder_index: 2,
            share_bcs: b"share".to_vec(),
        };
        store.put_holder_share(share.clone()).unwrap();
        assert_eq!(
            store.get_holder_share(session, 2).unwrap(),
            Some(HolderShareRecord {
                session_addr: normalize_account_addr(session),
                ..share
            })
        );
    }

    #[test]
    fn connect_vss_store_reuses_process_singleton_for_same_url() {
        let dir = tempfile::tempdir().unwrap();
        let url = format!("sqlite://{}", dir.path().join("vss.db").display());
        let first = connect_vss_store(&url).unwrap();
        let second = connect_vss_store(&url).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
    }

    #[test]
    fn prune_deletes_epoch_x_minus_two_and_older() {
        let (_dir, store) = test_store();
        for epoch in 0..=4 {
            store
                .put_dealer_state(DealerStateRecord {
                    epoch,
                    session_addr: format!("0x{epoch:x}"),
                    state_bytes: vec![epoch as u8],
                })
                .unwrap();
        }

        store.prune_at_epoch_start(4).unwrap();
        assert!(store.get_dealer_state("0x0").unwrap().is_none());
        assert!(store.get_dealer_state("0x1").unwrap().is_none());
        assert!(store.get_dealer_state("0x2").unwrap().is_none());
        assert!(store.get_dealer_state("0x3").unwrap().is_some());
        assert!(store.get_dealer_state("0x4").unwrap().is_some());
    }

    #[test]
    fn prune_except_sessions_keeps_only_reachable_vss_sessions() {
        let (_dir, store) = test_store();
        let live = normalize_account_addr("0x1");
        let stale = normalize_account_addr("0x2");

        for (epoch, session) in [(0, live.as_str()), (99, stale.as_str())] {
            store
                .put_dealer_state(DealerStateRecord {
                    epoch,
                    session_addr: session.to_string(),
                    state_bytes: vec![epoch as u8],
                })
                .unwrap();
            store
                .put_holder_share(HolderShareRecord {
                    epoch,
                    session_addr: session.to_string(),
                    holder_index: 0,
                    share_bcs: vec![epoch as u8],
                })
                .unwrap();
        }

        let deleted = store
            .prune_except_sessions(std::slice::from_ref(&live))
            .unwrap();
        assert_eq!(deleted, 2);
        assert!(store.get_dealer_state(&live).unwrap().is_some());
        assert!(store.get_holder_share(&live, 0).unwrap().is_some());
        assert!(store.get_dealer_state(&stale).unwrap().is_none());
        assert!(store.get_holder_share(&stale, 0).unwrap().is_none());
    }
}
