use std::sync::Arc;
use std::time::Duration;

use haos_green::config::MemoryConfig;
use haos_green::memory::MemoryStore;
use haos_green::supervisor::store::TaskStore;
use tokio::sync::Barrier;

/// Wall-clock epoch seconds — the same unit the lease columns are stored in.
fn epoch_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// The whole `sup_execution_leases` table as
/// `(task_id, owner_id, expires_at, renewed_at)` rows. Reading the row directly
/// is what lets a failure name the mechanism — two rows, a dead expiry, the
/// wrong owner — instead of only reporting the two booleans.
async fn lease_rows(store: &MemoryStore) -> Vec<(String, String, i64, i64)> {
    let conn = store.connection();
    let conn = conn.lock().await;
    let mut stmt = conn
        .prepare("SELECT task_id, owner_id, expires_at, renewed_at FROM sup_execution_leases")
        .unwrap();
    let rows = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .unwrap();
    rows.map(|r| r.unwrap()).collect()
}

/// Two independent stores model two supervisor processes opening the same DB.
/// The barrier ensures both acquisition attempts are live before either runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn independent_stores_allow_exactly_one_lease_owner() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("shared.sqlite");
    let first = MemoryStore::open(&db, None, MemoryConfig::default()).unwrap();
    let second = MemoryStore::open(&db, None, MemoryConfig::default()).unwrap();
    let left = TaskStore::new(first.connection());
    let right = TaskStore::new(second.connection());
    let barrier = Arc::new(Barrier::new(2));

    let left_barrier = Arc::clone(&barrier);
    let left_task = tokio::spawn(async move {
        left_barrier.wait().await;
        left.acquire_lease("same-task", "process-a", 60).await
    });
    let right_barrier = Arc::clone(&barrier);
    let right_task = tokio::spawn(async move {
        right_barrier.wait().await;
        right.acquire_lease("same-task", "process-b", 60).await
    });

    let (left, right) = tokio::time::timeout(Duration::from_secs(5), async {
        (
            left_task.await.unwrap().unwrap(),
            right_task.await.unwrap().unwrap(),
        )
    })
    .await
    .expect("concurrent lease acquisition must not hang");

    // Read the row the race left behind *before* asserting: if the
    // exactly-one-winner assertion ever fails again, the message must carry the
    // evidence (both answers, the clock, the row) rather than just `left: 2`.
    let now = epoch_now();
    let rows = lease_rows(&second).await;
    let diag = format!(
        "process-a={left} process-b={right} now={now} \
         rows(task_id,owner_id,expires_at,renewed_at)={rows:?}"
    );
    assert_eq!(usize::from(left) + usize::from(right), 1, "{diag}");
    assert_eq!(rows.len(), 1, "exactly one lease row expected; {diag}");
    let (task_id, owner_id, expires_at, renewed_at) = rows[0].clone();
    let winner = if left { "process-a" } else { "process-b" };
    assert_eq!(
        task_id, "same-task",
        "the row must be the raced task; {diag}"
    );
    assert_eq!(
        owner_id, winner,
        "the row must belong to the winner; {diag}"
    );
    assert!(
        expires_at > now,
        "the winning lease must be live (expires_at={expires_at} \
         renewed_at={renewed_at} now={now}); {diag}"
    );
}

/// The same invariant with no scheduling at all: one live lease, one owner, and
/// the row itself says who holds it. Expiry is forced with SQL instead of slept
/// for, so nothing here depends on timing or clock granularity.
#[tokio::test]
async fn a_live_lease_refuses_a_second_owner_and_an_expired_one_hands_over() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("shared.sqlite");
    let first = MemoryStore::open(&db, None, MemoryConfig::default()).unwrap();
    let second = MemoryStore::open(&db, None, MemoryConfig::default()).unwrap();
    let a = TaskStore::new(first.connection());
    let b = TaskStore::new(second.connection());

    assert!(a.acquire_lease("same-task", "process-a", 60).await.unwrap());
    assert!(
        !b.acquire_lease("same-task", "process-b", 60).await.unwrap(),
        "a live lease must refuse a second owner"
    );

    let rows = lease_rows(&second).await;
    assert_eq!(rows.len(), 1, "one lease row; got {rows:?}");
    let (task_id, owner_id, expires_at, _) = rows[0].clone();
    assert_eq!(task_id, "same-task");
    assert_eq!(
        owner_id, "process-a",
        "the refused claim must not move the row; {rows:?}"
    );
    assert!(
        expires_at > epoch_now(),
        "the lease must still be live; {rows:?}"
    );

    // Force the condition the takeover tests (`expires_at <= now`) rather than
    // waiting a TTL out.
    {
        let conn = second.connection();
        let conn = conn.lock().await;
        conn.execute("UPDATE sup_execution_leases SET expires_at=0", [])
            .unwrap();
    }
    assert!(
        b.acquire_lease("same-task", "process-b", 60).await.unwrap(),
        "an expired lease must be takeable by a new owner"
    );

    let rows = lease_rows(&second).await;
    assert_eq!(rows.len(), 1, "one lease row after takeover; got {rows:?}");
    let (task_id, owner_id, expires_at, _) = rows[0].clone();
    assert_eq!(task_id, "same-task");
    assert_eq!(
        owner_id, "process-b",
        "the new owner must own the row; {rows:?}"
    );
    assert!(
        expires_at > epoch_now(),
        "the takeover must write a live expiry; {rows:?}"
    );
}

/// A non-positive TTL is refused outright and writes nothing: a zero TTL would
/// store `expires_at = now`, an already-expired lease every competing process
/// could take over immediately.
#[tokio::test]
async fn a_non_positive_ttl_is_refused_and_writes_no_row() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("shared.sqlite");
    let memory = MemoryStore::open(&db, None, MemoryConfig::default()).unwrap();
    let store = TaskStore::new(memory.connection());

    let err = store
        .acquire_lease("same-task", "process-a", 0)
        .await
        .expect_err("a zero TTL must be refused");
    assert!(
        err.to_string().contains("TTL must be positive"),
        "unexpected error: {err}"
    );
    assert!(store
        .acquire_lease("same-task", "process-a", -60)
        .await
        .is_err());
    assert!(
        lease_rows(&memory).await.is_empty(),
        "a refused claim must not write a lease row"
    );
}

#[tokio::test]
async fn failed_owner_cannot_release_another_process_lease() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("shared.sqlite");
    let first = MemoryStore::open(&db, None, MemoryConfig::default()).unwrap();
    let second = MemoryStore::open(&db, None, MemoryConfig::default()).unwrap();
    let owner = TaskStore::new(first.connection());
    let failed = TaskStore::new(second.connection());

    assert!(owner
        .acquire_lease("same-task", "process-a", 60)
        .await
        .unwrap());
    assert!(!failed
        .release_lease("same-task", "process-b")
        .await
        .unwrap());
    assert!(owner.release_lease("same-task", "process-a").await.unwrap());
    assert!(failed
        .acquire_lease("same-task", "process-b", 60)
        .await
        .unwrap());
}

/// The takeover a heartbeat has to notice: once the lease has expired and
/// another process holds it, the old owner can neither renew nor release it.
/// Those two `false` answers are exactly what the heartbeat turns into "lease
/// lost" and what `LeaseGuard::release` turns into an error — and the new
/// owner's lease must survive both.
#[tokio::test]
async fn a_taken_over_lease_can_neither_be_renewed_nor_released_by_the_old_owner() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("shared.sqlite");
    let first = MemoryStore::open(&db, None, MemoryConfig::default()).unwrap();
    let second = MemoryStore::open(&db, None, MemoryConfig::default()).unwrap();
    let old = TaskStore::new(first.connection());
    let new = TaskStore::new(second.connection());

    assert!(old
        .acquire_lease("same-task", "process-a", 60)
        .await
        .unwrap());
    // Process A stalls past its TTL and process B takes the task over.
    {
        let conn = second.connection();
        let conn = conn.lock().await;
        conn.execute("UPDATE sup_execution_leases SET expires_at=0", [])
            .unwrap();
    }
    assert!(new
        .acquire_lease("same-task", "process-b", 60)
        .await
        .unwrap());

    assert!(!old.renew_lease("same-task", "process-a", 60).await.unwrap());
    assert!(!old.release_lease("same-task", "process-a").await.unwrap());
    assert!(
        new.renew_lease("same-task", "process-b", 60).await.unwrap(),
        "the new owner's lease must survive the old owner's failed release"
    );
}

/// The other half of the takeover: the process that took the lease over owns
/// it, so it can renew it and release it — and the row is really gone
/// afterwards, which is what frees the task for the next run.
#[tokio::test]
async fn the_new_owner_can_renew_and_release_the_lease_it_took_over() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("shared.sqlite");
    let first = MemoryStore::open(&db, None, MemoryConfig::default()).unwrap();
    let second = MemoryStore::open(&db, None, MemoryConfig::default()).unwrap();
    let old = TaskStore::new(first.connection());
    let new = TaskStore::new(second.connection());

    assert!(old
        .acquire_lease("same-task", "process-a", 60)
        .await
        .unwrap());
    // A renewal from a non-owner is denied even while the lease is live.
    assert!(!new.renew_lease("same-task", "process-b", 60).await.unwrap());

    {
        let conn = first.connection();
        let conn = conn.lock().await;
        conn.execute("UPDATE sup_execution_leases SET expires_at=0", [])
            .unwrap();
    }
    assert!(new
        .acquire_lease("same-task", "process-b", 60)
        .await
        .unwrap());

    assert!(new.renew_lease("same-task", "process-b", 60).await.unwrap());
    assert!(new.release_lease("same-task", "process-b").await.unwrap());
    // Released means free: the next owner can take it.
    assert!(old
        .acquire_lease("same-task", "process-c", 60)
        .await
        .unwrap());
}
