//! Logs command implementation

use crate::cli::LogsArgs;
use crate::client::create_client;
use crate::error::{KcError, Result};
use futures::{AsyncBufReadExt, TryStreamExt};
use k8s_openapi::api::core::v1::Pod;
use kube::api::LogParams;
use kube::Api;
use std::io::Write;

/// Run the logs command
pub async fn run_logs(
    context: Option<&str>,
    namespace: Option<&str>,
    args: &LogsArgs,
) -> Result<()> {
    let client = create_client(context).await?;
    let ns = namespace.unwrap_or("default");
    let api: Api<Pod> = Api::namespaced(client.clone(), ns);

    // Build log params
    let mut lp = LogParams::default();

    if let Some(container) = &args.container {
        lp.container = Some(container.clone());
    }

    lp.tail_lines = Some(args.tail);

    if let Some(since) = &args.since {
        lp.since_seconds = Some(parse_duration_to_seconds(since)?);
    }

    if args.timestamps {
        lp.timestamps = true;
    }

    if args.previous {
        lp.previous = true;
    }

    if args.follow {
        // Streaming logs
        lp.follow = true;
        stream_logs(&api, &args.pod, &lp).await
    } else {
        // One-shot logs
        let logs = api.logs(&args.pod, &lp).await?;
        print!("{}", logs);
        Ok(())
    }
}

/// Stream logs to stdout
async fn stream_logs(api: &Api<Pod>, pod_name: &str, params: &LogParams) -> Result<()> {
    let mut stream = api
        .log_stream(pod_name, params)
        .await?
        .lines();

    while let Some(line) = stream.try_next().await? {
        println!("{}", line);
        std::io::stdout().flush().ok();
    }

    Ok(())
}

/// Parse duration string to seconds (e.g., "1h", "30m", "10s", "1h30m")
fn parse_duration_to_seconds(s: &str) -> Result<i64> {
    // Try to parse with humantime
    match humantime::parse_duration(s) {
        Ok(duration) => Ok(duration.as_secs() as i64),
        Err(_) => {
            // Try simple format: number + unit
            let s = s.trim();
            if s.is_empty() {
                return Err(KcError::InvalidArgument("Empty duration".to_string()));
            }

            let mut total_seconds: i64 = 0;
            let mut current_num = String::new();

            for c in s.chars() {
                if c.is_ascii_digit() {
                    current_num.push(c);
                } else {
                    if current_num.is_empty() {
                        return Err(KcError::InvalidArgument(format!(
                            "Invalid duration format: {}",
                            s
                        )));
                    }
                    let num: i64 = current_num.parse().map_err(|_| {
                        KcError::InvalidArgument(format!("Invalid number in duration: {}", s))
                    })?;
                    current_num.clear();

                    match c {
                        's' => total_seconds += num,
                        'm' => total_seconds += num * 60,
                        'h' => total_seconds += num * 3600,
                        'd' => total_seconds += num * 86400,
                        _ => {
                            return Err(KcError::InvalidArgument(format!(
                                "Unknown duration unit '{}' in: {}",
                                c, s
                            )))
                        }
                    }
                }
            }

            // If there's a trailing number without unit, treat as seconds
            if !current_num.is_empty() {
                let num: i64 = current_num.parse().map_err(|_| {
                    KcError::InvalidArgument(format!("Invalid number in duration: {}", s))
                })?;
                total_seconds += num;
            }

            if total_seconds == 0 {
                return Err(KcError::InvalidArgument(format!(
                    "Duration must be greater than 0: {}",
                    s
                )));
            }

            Ok(total_seconds)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration_to_seconds("30s").unwrap(), 30);
        assert_eq!(parse_duration_to_seconds("5m").unwrap(), 300);
        assert_eq!(parse_duration_to_seconds("1h").unwrap(), 3600);
        assert_eq!(parse_duration_to_seconds("1d").unwrap(), 86400);
        assert_eq!(parse_duration_to_seconds("1h30m").unwrap(), 5400);
    }
}
