use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use fishnet_types::config::FishnetConfig;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::{mpsc, watch};

use crate::config::load_config;

fn watch_dir_for_config_path(config_path: &std::path::Path) -> PathBuf {
    match config_path.parent() {
        Some(parent) if parent.as_os_str().is_empty() => PathBuf::from("."),
        Some(parent) => parent.to_path_buf(),
        None => PathBuf::from("."),
    }
}

pub fn spawn_config_watcher(
    config_path: PathBuf,
    config_tx: watch::Sender<Arc<FishnetConfig>>,
) -> (tokio::task::JoinHandle<()>, RecommendedWatcher) {
    let (event_tx, mut event_rx) = mpsc::channel::<()>(1);

    let file_name = config_path
        .file_name()
        .expect("config path must have a filename")
        .to_os_string();

    let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
        if let Ok(event) = res
            && matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_))
        {
            let dominated = event.paths.is_empty()
                || event
                    .paths
                    .iter()
                    .any(|p| p.file_name() == Some(&file_name));
            if dominated {
                let _ = event_tx.try_send(());
            }
        }
    })
    .expect("failed to create file watcher");

    let watch_dir = watch_dir_for_config_path(&config_path);

    watcher
        .watch(&watch_dir, RecursiveMode::NonRecursive)
        .expect("failed to watch config directory");

    let handle = tokio::spawn(async move {
        loop {
            if event_rx.recv().await.is_none() {
                break;
            }

            tokio::time::sleep(Duration::from_millis(200)).await;
            while event_rx.try_recv().is_ok() {}

            match load_config(Some(&config_path)) {
                Ok(new_config) => {
                    eprintln!("[fishnet] config reloaded from {}", config_path.display());
                    let _ = config_tx.send(Arc::new(new_config));
                }
                Err(e) => {
                    eprintln!("[fishnet] config reload failed, keeping previous config: {e}");
                }
            }
        }
    });

    (handle, watcher)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::config_channel;

    #[test]
    fn watch_dir_for_relative_config_uses_current_dir() {
        let dir = watch_dir_for_config_path(std::path::Path::new("fishnet.toml"));
        assert_eq!(dir, PathBuf::from("."));
    }

    #[tokio::test]
    async fn watcher_detects_config_change() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fishnet.toml");

        std::fs::write(
            &path,
            "[llm.prompt_size_guard]\nmax_prompt_tokens = 50000\n",
        )
        .unwrap();

        let initial = FishnetConfig::default();
        let (tx, mut rx) = config_channel(initial);

        let (_handle, _watcher) = spawn_config_watcher(path.clone(), tx);

        tokio::time::sleep(Duration::from_millis(200)).await;

        std::fs::write(
            &path,
            "[llm.prompt_size_guard]\nmax_prompt_tokens = 99999\n",
        )
        .unwrap();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            match tokio::time::timeout(Duration::from_millis(500), rx.changed()).await {
                Ok(Ok(())) => {
                    let config = rx.borrow().clone();
                    if config.llm.prompt_size_guard.max_prompt_tokens == 99999 {
                        break;
                    }
                }
                Ok(Err(_)) => panic!("watch channel closed"),
                Err(_) => {}
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for config change"
            );
        }

        let config = rx.borrow().clone();
        assert_eq!(config.llm.prompt_size_guard.max_prompt_tokens, 99999);
    }

    #[tokio::test]
    async fn watcher_keeps_old_config_on_invalid_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fishnet.toml");

        std::fs::write(
            &path,
            "[llm.prompt_size_guard]\nmax_prompt_tokens = 50000\n",
        )
        .unwrap();

        let initial = FishnetConfig::default();
        let (tx, rx) = config_channel(initial);

        let (_handle, _watcher) = spawn_config_watcher(path.clone(), tx);

        tokio::time::sleep(Duration::from_millis(200)).await;

        std::fs::write(&path, "not valid [[[").unwrap();

        tokio::time::sleep(Duration::from_secs(1)).await;
        let config = rx.borrow().clone();
        assert_eq!(config.llm.prompt_size_guard.max_prompt_tokens, 50_000);
    }
}
