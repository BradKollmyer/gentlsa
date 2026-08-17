use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::publish::PublisherKind;
use crate::tlsa::StarttlsProto;
use crate::verbose;

/// Cloudflare "auto" TTL is 300s; other publishers default to 3600.
pub fn default_ttl(kind: PublisherKind) -> u32 {
    match kind {
        PublisherKind::Cloudflare => 300,
        PublisherKind::Nsupdate
        | PublisherKind::Route53
        | PublisherKind::Google
        | PublisherKind::Azure => 3600,
    }
}

/// RFC 7671 §8.1: publish the new hash at least two TTLs before deploying the new chain.
pub const WAIT_TTL_MULTIPLIER: u64 = 2;

pub fn wait_seconds(ttl: u32) -> u64 {
    u64::from(ttl).saturating_mul(WAIT_TTL_MULTIPLIER)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitReason {
    BeforeReload,
    BeforePrune,
}

impl WaitReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BeforeReload => "before reload",
            Self::BeforePrune => "before prune",
        }
    }
}

/// Automated sequence when `--reload` is set. Without it, only publish runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Publish,
    Wait(WaitReason),
    Reload,
    Prune,
}

pub fn phases(reload: bool) -> &'static [Phase] {
    if reload {
        &[
            Phase::Publish,
            Phase::Wait(WaitReason::BeforeReload),
            Phase::Reload,
            Phase::Wait(WaitReason::BeforePrune),
            Phase::Prune,
        ]
    } else {
        &[Phase::Publish]
    }
}

pub fn next_steps(
    zone: &str,
    ports: &[u16],
    hostname: Option<&str>,
    kind: PublisherKind,
    ttl: u32,
    starttls: Option<StarttlsProto>,
) -> String {
    let ports = ports
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let mut prune = format!("gentlsa prune {zone} {ports} {}", kind.flag());
    if let Some(host) = hostname.filter(|host| !host.is_empty()) {
        prune.push_str(" --hostname ");
        prune.push_str(host);
    }
    if let Some(proto) = starttls {
        prune.push_str(" --starttls ");
        prune.push_str(proto.as_str());
    }
    let wait = wait_seconds(ttl);
    format!(
        ">>> Next: wait {wait}s (2× TLSA TTL), reload the service so it presents the new certificate, wait another {wait}s, then:\n    {prune}"
    )
}

pub fn wait_banner(ttl: u32, reason: WaitReason, dryrun: bool) -> String {
    if dryrun {
        format!(
            ">>> dry run: would wait {ttl}s for TLSA TTL {}",
            reason.as_str()
        )
    } else {
        format!(">>> Wait {ttl}s for TLSA TTL {}", reason.as_str())
    }
}

pub fn reload_banner(command: &str, dryrun: bool) -> String {
    if dryrun {
        format!(">>> dry run: would run: {command}")
    } else {
        format!(">>> Reload: {command}")
    }
}

pub async fn wait_ttl(ttl: u64, reason: WaitReason, dryrun: bool) {
    let shown = u32::try_from(ttl.min(u64::from(u32::MAX))).unwrap_or(u32::MAX);
    crate::output::text(wait_banner(shown, reason, dryrun));
    if dryrun || ttl == 0 {
        return;
    }
    verbose::step(format_args!("sleeping {ttl}s {}", reason.as_str()));
    tokio::time::sleep(std::time::Duration::from_secs(ttl)).await;
    // The wait is deliberate and can run for hours; it must not consume the
    // connect/IO budget that the next phase needs.
    crate::timeout::restart();
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn remaining(deadline: Option<u64>, now: u64) -> u64 {
    deadline.unwrap_or(now).saturating_sub(now)
}

const JOB_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobPhase {
    Publish,
    WaitBeforeReload,
    Reload,
    WaitBeforePrune,
    Prune,
}

impl JobPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Publish => "publish",
            Self::WaitBeforeReload => "wait_before_reload",
            Self::Reload => "reload",
            Self::WaitBeforePrune => "wait_before_prune",
            Self::Prune => "prune",
        }
    }

    pub fn start_index(self) -> usize {
        match self {
            Self::Publish => 0,
            Self::WaitBeforeReload => 1,
            Self::Reload => 2,
            Self::WaitBeforePrune => 3,
            Self::Prune => 4,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub version: u32,
    pub id: String,
    pub certfile: PathBuf,
    pub zone: String,
    pub ports: Vec<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub starttls: Option<StarttlsProto>,
    pub publisher: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reload: Option<String>,
    pub ttl: u32,
    pub certificate: String,
    pub phase: JobPhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reload_after: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reloaded_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prune_after: Option<u64>,
}

impl Job {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        certfile: PathBuf,
        zone: String,
        ports: &[u16],
        hostname: Option<&str>,
        kind: PublisherKind,
        reload: Option<String>,
        ttl: u32,
        certificate: String,
        starttls: Option<StarttlsProto>,
    ) -> Self {
        let hostname = hostname.filter(|host| !host.is_empty()).map(str::to_string);
        Self {
            version: JOB_VERSION,
            id: job_id(&zone, hostname.as_deref(), ports),
            certfile,
            zone,
            ports: ports.to_vec(),
            hostname,
            starttls,
            publisher: kind.name().into(),
            reload,
            ttl,
            certificate,
            phase: JobPhase::Publish,
            published_at: None,
            reload_after: None,
            reloaded_at: None,
            prune_after: None,
        }
    }

    pub fn kind(&self) -> Result<PublisherKind> {
        PublisherKind::from_name(&self.publisher)
            .with_context(|| format!("unknown publisher in job {}: {}", self.id, self.publisher))
    }

    pub fn mark_published(&mut self, now: u64) {
        self.published_at = Some(now);
        let wait = wait_seconds(self.ttl);
        self.reload_after = Some(now + wait);
        self.prune_after = Some(now + wait.saturating_mul(2));
        self.phase = if self.reload.is_some() {
            JobPhase::WaitBeforeReload
        } else {
            JobPhase::Prune
        };
    }

    pub fn mark_reloaded(&mut self, now: u64) {
        self.reloaded_at = Some(now);
        let prune_at = now + wait_seconds(self.ttl);
        self.prune_after = Some(self.prune_after.unwrap_or(prune_at).max(prune_at));
        self.phase = JobPhase::WaitBeforePrune;
    }

    /// Reboot (or other implicit reload) already presents the new cert.
    pub fn mark_already_live(&mut self, now: u64) {
        self.mark_reloaded(now);
    }

    pub fn mark_waiting_reload(&mut self) {
        self.phase = JobPhase::Reload;
    }

    pub fn mark_ready_to_prune(&mut self) {
        self.phase = JobPhase::Prune;
    }

    pub fn unit_name(&self) -> String {
        format!("gentlsa-rollover@{}.service", self.id)
    }
}

pub fn job_id(zone: &str, hostname: Option<&str>, ports: &[u16]) -> String {
    let zone = zone.trim_end_matches('.');
    let base = match hostname.filter(|host| !host.is_empty()) {
        Some(host) => format!("{host}.{zone}"),
        None => zone.to_string(),
    };
    let safe: String = base
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let ports = ports
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("-");
    format!("{safe}_{ports}")
}

pub fn valid_job_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() < 200
        && !id.contains("..")
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

pub fn state_dir() -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("GENTLSA_STATE_DIR") {
        let dir = PathBuf::from(dir);
        fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;
        return Ok(dir);
    }
    let system = PathBuf::from("/var/lib/gentlsa/rollover");
    if mkdir_if_possible(&system) {
        return Ok(system);
    }
    let user = dirs::data_local_dir()
        .or_else(dirs::home_dir)
        .map(|base| base.join("gentlsa").join("rollover"))
        .context("cannot determine a state directory (set GENTLSA_STATE_DIR)")?;
    fs::create_dir_all(&user).with_context(|| format!("failed to create {}", user.display()))?;
    Ok(user)
}

fn mkdir_if_possible(path: &Path) -> bool {
    path.is_dir() || fs::create_dir_all(path).is_ok()
}

pub fn job_path(dir: &Path, id: &str) -> PathBuf {
    dir.join(format!("{id}.json"))
}

pub fn save_job_in(dir: &Path, job: &Job) -> Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("failed to create {}", dir.display()))?;
    let path = job_path(dir, &job.id);
    let tmp = path.with_extension("json.tmp");
    let data = serde_json::to_vec_pretty(job).context("failed to serialize rollover job")?;
    fs::write(&tmp, data).with_context(|| format!("failed to write {}", tmp.display()))?;
    fs::rename(&tmp, &path).with_context(|| format!("failed to write {}", path.display()))?;
    verbose::step(format_args!("saved rollover job {}", path.display()));
    Ok(())
}

pub fn save_job(job: &Job) -> Result<()> {
    save_job_in(&state_dir()?, job)
}

pub fn remove_job_in(dir: &Path, id: &str) -> Result<()> {
    let path = job_path(dir, id);
    match fs::remove_file(&path) {
        Ok(()) => {
            verbose::step(format_args!("removed rollover job {}", path.display()));
            Ok(())
        }
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("failed to remove {}", path.display())),
    }
}

pub fn remove_job(id: &str) -> Result<()> {
    remove_job_in(&state_dir()?, id)
}

pub fn load_job_in(dir: &Path, id: &str) -> Result<Option<Job>> {
    if !valid_job_id(id) {
        bail!("invalid rollover job id {id}");
    }
    let path = job_path(dir, id);
    if !path.is_file() {
        return Ok(None);
    }
    let data = fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let job: Job = serde_json::from_slice(&data)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    if job.version != JOB_VERSION {
        bail!(
            "unsupported rollover job version {} in {}",
            job.version,
            path.display()
        );
    }
    Ok(Some(job))
}

pub fn load_jobs_in(dir: &Path, filter: Option<&str>) -> Result<Vec<Job>> {
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut jobs = Vec::new();
    for entry in fs::read_dir(dir).with_context(|| format!("failed to read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        if !valid_job_id(stem) {
            continue;
        }
        if let Some(job) = load_job_in(dir, stem)? {
            jobs.push(job);
        }
    }
    jobs.sort_by(|a, b| a.id.cmp(&b.id));
    let Some(filter) = filter.filter(|filter| *filter != "*") else {
        return Ok(jobs);
    };
    if !valid_job_id(filter) {
        bail!("invalid rollover job id {filter}");
    }
    let matched: Vec<Job> = jobs
        .into_iter()
        .filter(|job| {
            job.id == filter
                || job.zone.eq_ignore_ascii_case(filter)
                || job.id.starts_with(&format!("{filter}_"))
        })
        .collect();
    if matched.is_empty() {
        bail!("no pending rollover matching {filter}");
    }
    Ok(matched)
}

pub fn load_jobs(filter: Option<&str>) -> Result<Vec<Job>> {
    load_jobs_in(&state_dir()?, filter)
}

pub struct JobGuard {
    lock_dir: PathBuf,
}

impl Drop for JobGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.lock_dir);
    }
}

pub fn acquire_in(dir: &Path, id: &str) -> Result<Option<JobGuard>> {
    if !valid_job_id(id) {
        bail!("invalid rollover job id {id}");
    }
    fs::create_dir_all(dir).with_context(|| format!("failed to create {}", dir.display()))?;
    let lock_dir = dir.join(format!("{id}.lock"));
    for _ in 0..3 {
        match fs::create_dir(&lock_dir) {
            Ok(()) => {
                let pid = std::process::id();
                fs::write(lock_dir.join("pid"), pid.to_string())
                    .with_context(|| format!("failed to write {}", lock_dir.display()))?;
                verbose::step(format_args!("locked rollover job {id} (pid {pid})"));
                return Ok(Some(JobGuard { lock_dir }));
            }
            Err(err) if err.kind() == ErrorKind::AlreadyExists => {
                if lock_is_stale(&lock_dir) {
                    verbose::step(format_args!("removing stale lock {}", lock_dir.display()));
                    let _ = fs::remove_dir_all(&lock_dir);
                    continue;
                }
                return Ok(None);
            }
            Err(err) => {
                return Err(err).with_context(|| format!("failed to lock {}", lock_dir.display()));
            }
        }
    }
    Ok(None)
}

pub fn acquire(id: &str) -> Result<Option<JobGuard>> {
    acquire_in(&state_dir()?, id)
}

fn lock_is_stale(lock_dir: &Path) -> bool {
    let Ok(data) = fs::read_to_string(lock_dir.join("pid")) else {
        return true;
    };
    let Ok(pid) = data.trim().parse::<u32>() else {
        return true;
    };
    !pid_is_running(pid)
}

fn pid_is_running(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    if Path::new(&format!("/proc/{pid}")).exists() {
        return true;
    }
    #[cfg(unix)]
    {
        std::process::Command::new("kill")
            .arg("-0")
            .arg(pid.to_string())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        false
    }
}

pub fn start_systemd_unit(job_id: &str) -> Result<()> {
    let unit = format!("gentlsa-rollover@{job_id}.service");
    verbose::step(format_args!("systemctl start --no-block {unit}"));
    let status = std::process::Command::new("systemctl")
        .args(["start", "--no-block", &unit])
        .status()
        .with_context(|| format!("failed to start {unit} (is systemd available?)"))?;
    if !status.success() {
        bail!(
            "systemctl start {unit} exited {}",
            status.code().unwrap_or(1)
        );
    }
    Ok(())
}

pub fn run_reload(command: &str) -> Result<i32> {
    verbose::step(format_args!("reload: {command}"));
    let status = reload_command(command)
        .status()
        .with_context(|| format!("failed to run --reload command: {command}"))?;
    let code = status.code().unwrap_or(1);
    if !status.success() {
        bail!("--reload command exited {code}: {command}");
    }
    Ok(code)
}

fn reload_command(command: &str) -> std::process::Command {
    if cfg!(windows) {
        let mut cmd = std::process::Command::new("cmd");
        cmd.arg("/C").arg(command);
        cmd
    } else {
        let mut cmd = std::process::Command::new("sh");
        cmd.arg("-c").arg(command);
        cmd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_ttl_by_publisher() {
        assert_eq!(default_ttl(PublisherKind::Cloudflare), 300);
        assert_eq!(default_ttl(PublisherKind::Nsupdate), 3600);
        assert_eq!(default_ttl(PublisherKind::Route53), 3600);
        assert_eq!(default_ttl(PublisherKind::Google), 3600);
        assert_eq!(default_ttl(PublisherKind::Azure), 3600);
    }

    #[test]
    fn wait_is_two_ttls() {
        assert_eq!(wait_seconds(0), 0);
        assert_eq!(wait_seconds(300), 600);
        assert_eq!(wait_seconds(3600), 7200);
        assert_eq!(wait_seconds(u32::MAX), u64::from(u32::MAX) * 2);
    }

    #[test]
    fn phases_depend_on_reload() {
        assert_eq!(phases(false), &[Phase::Publish]);
        assert_eq!(
            phases(true),
            &[
                Phase::Publish,
                Phase::Wait(WaitReason::BeforeReload),
                Phase::Reload,
                Phase::Wait(WaitReason::BeforePrune),
                Phase::Prune,
            ]
        );
    }

    #[test]
    fn next_steps_includes_prune_command() {
        let msg = next_steps(
            "example.com",
            &[443],
            None,
            PublisherKind::Cloudflare,
            300,
            None,
        );
        assert!(msg.contains("wait 600s (2× TLSA TTL)"));
        assert!(msg.contains("gentlsa prune example.com 443 --cloudflare"));
        assert!(!msg.contains("--hostname"));
        assert!(!msg.contains("--starttls"));

        let msg = next_steps(
            "example.com",
            &[25, 465],
            Some("mx"),
            PublisherKind::Nsupdate,
            3600,
            Some(StarttlsProto::Smtp),
        );
        assert!(
            msg.contains(
                "gentlsa prune example.com 25,465 --nsupdate --hostname mx --starttls smtp"
            )
        );
    }

    #[test]
    fn banners_mark_dryrun() {
        assert_eq!(
            wait_banner(300, WaitReason::BeforeReload, false),
            ">>> Wait 300s for TLSA TTL before reload"
        );
        assert_eq!(
            wait_banner(300, WaitReason::BeforeReload, true),
            ">>> dry run: would wait 300s for TLSA TTL before reload"
        );
        assert_eq!(
            reload_banner("systemctl reload nginx", true),
            ">>> dry run: would run: systemctl reload nginx"
        );
    }

    #[cfg(unix)]
    #[test]
    fn reload_true_succeeds() {
        assert_eq!(run_reload("true").unwrap(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn reload_false_fails() {
        let err = run_reload("false").unwrap_err();
        assert!(err.to_string().contains("exited 1"));
    }

    #[test]
    fn job_id_is_systemd_safe() {
        assert_eq!(job_id("example.com.", None, &[443]), "example.com_443");
        assert_eq!(
            job_id("example.com", Some("mx"), &[25, 465]),
            "mx.example.com_25-465"
        );
        assert!(valid_job_id("example.com_443"));
        assert!(valid_job_id("mx.example.com_25-465"));
        assert!(!valid_job_id("../etc/passwd"));
        assert!(!valid_job_id("has space"));
        assert!(!valid_job_id(""));
    }

    #[test]
    fn remaining_and_phase_index() {
        assert_eq!(remaining(Some(100), 40), 60);
        assert_eq!(remaining(Some(40), 100), 0);
        assert_eq!(remaining(None, 10), 0);
        assert_eq!(JobPhase::Publish.start_index(), 0);
        assert_eq!(JobPhase::Prune.start_index(), 4);
    }

    #[test]
    fn mark_published_and_already_live() {
        let mut job = Job::new(
            "cert.pem".into(),
            "example.com".into(),
            &[443],
            None,
            PublisherKind::Cloudflare,
            Some("systemctl reload nginx".into()),
            300,
            "abc".into(),
            None,
        );
        job.mark_published(1_000);
        assert_eq!(job.phase, JobPhase::WaitBeforeReload);
        assert_eq!(job.reload_after, Some(1_600));
        assert_eq!(job.prune_after, Some(2_200));

        job.mark_already_live(1_100);
        assert_eq!(job.phase, JobPhase::WaitBeforePrune);
        assert_eq!(job.reloaded_at, Some(1_100));
        // keep the original prune deadline when it is later
        assert_eq!(job.prune_after, Some(2_200));

        job.mark_already_live(1_700);
        assert_eq!(job.prune_after, Some(2_300));
    }

    fn test_dir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "gentlsa-job-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn job_roundtrip_and_filter() {
        let dir = test_dir();
        let job = Job::new(
            "cert.pem".into(),
            "example.com".into(),
            &[443],
            None,
            PublisherKind::Cloudflare,
            Some("true".into()),
            300,
            "abc".into(),
            Some(StarttlsProto::Imap),
        );
        save_job_in(&dir, &job).unwrap();
        let loaded = load_job_in(&dir, &job.id).unwrap().unwrap();
        assert_eq!(loaded.certificate, "abc");
        assert_eq!(loaded.publisher, "cloudflare");
        assert_eq!(loaded.starttls, Some(StarttlsProto::Imap));

        let found = load_jobs_in(&dir, Some("example.com")).unwrap();
        assert_eq!(found.len(), 1);
        assert!(load_jobs_in(&dir, Some("other.org")).is_err());
        remove_job_in(&dir, &job.id).unwrap();
        assert!(load_job_in(&dir, &job.id).unwrap().is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn job_without_starttls_field_still_loads() {
        let dir = test_dir();
        let path = dir.join("example.com_443.json");
        fs::write(
            &path,
            r#"{
              "version": 1,
              "id": "example.com_443",
              "certfile": "cert.pem",
              "zone": "example.com",
              "ports": [443],
              "publisher": "cloudflare",
              "ttl": 300,
              "certificate": "abc",
              "phase": "publish"
            }"#,
        )
        .unwrap();
        let job = load_job_in(&dir, "example.com_443").unwrap().unwrap();
        assert!(job.starttls.is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn lock_reclaims_stale_pid() {
        let dir = test_dir();
        let lock = dir.join("example.com_443.lock");
        fs::create_dir(&lock).unwrap();
        fs::write(lock.join("pid"), "4194304\n").unwrap();
        let guard = acquire_in(&dir, "example.com_443").unwrap();
        assert!(guard.is_some());
        drop(guard);
        assert!(!lock.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    /// The whole point of the fix: a rollover wait is deliberate and can run
    /// for hours, so the next phase must not inherit an exhausted budget.
    /// Before this, `rollover --reload` always died in the prune phase with
    /// "timed out after Ns" and left the job file behind.
    // The guard is held across the sleep on purpose: it serializes the
    // process-wide timeout state against the other test that mutates it.
    // Each #[tokio::test] gets its own current-thread runtime, so no other
    // task can contend for this lock while it is held.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn wait_ttl_rearms_the_timeout_budget() {
        let _guard = crate::timeout::TEST_LOCK
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        crate::timeout::init_for_test(std::time::Duration::from_millis(20));

        wait_ttl(1, WaitReason::BeforePrune, false).await;

        assert!(
            crate::timeout::remaining().is_ok(),
            "a wait longer than the budget must not leave the next phase expired"
        );
        crate::timeout::clear_for_test();
    }

    /// A dry run does not sleep, so it has nothing to re-arm.
    #[tokio::test]
    async fn wait_ttl_dryrun_does_not_sleep() {
        let started = std::time::Instant::now();
        wait_ttl(3600, WaitReason::BeforeReload, true).await;
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }
}
