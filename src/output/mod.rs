//! Output formatting for kubecontrol

use crate::resources::{status_category, StatusCategory, Tabular};
use owo_colors::OwoColorize;

/// Format a list of resources as a table
pub fn format_table<T: Tabular>(resources: &[T], wide: bool) -> String {
    if resources.is_empty() {
        return "No resources found".to_string();
    }

    let headers: Vec<&str> = if wide {
        T::headers_wide()
    } else {
        T::headers()
    };

    let rows: Vec<Vec<String>> = resources
        .iter()
        .map(|r| {
            let row = if wide { r.row_wide() } else { r.row() };
            // Apply coloring to status column if applicable
            if let Some(status) = r.status_for_color() {
                row.into_iter()
                    .map(|cell| {
                        if cell == status {
                            colorize_status(&cell)
                        } else {
                            cell
                        }
                    })
                    .collect()
            } else {
                row
            }
        })
        .collect();

    format_table_raw(&headers, &rows)
}

/// Format raw headers and rows as a table
pub fn format_table_raw(headers: &[&str], rows: &[Vec<String>]) -> String {
    // Calculate column widths
    let num_cols = headers.len();
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();

    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if i < num_cols {
                widths[i] = widths[i].max(strip_ansi_codes(cell).len());
            }
        }
    }

    let mut output = String::new();

    // Format header row
    let mut header_line = String::new();
    for (i, header) in headers.iter().enumerate() {
        let padding = widths[i].saturating_sub(header.len());
        header_line.push_str(header);
        header_line.push_str(&" ".repeat(padding + 2));
    }
    output.push_str(&header_line.trim_end().bold().to_string());
    output.push('\n');

    // Format data rows
    for row in rows {
        let mut line = String::new();
        for (i, cell) in row.iter().enumerate() {
            if i < num_cols {
                let stripped_len = strip_ansi_codes(cell).len();
                let padding = widths[i].saturating_sub(stripped_len);
                line.push_str(cell);
                line.push_str(&" ".repeat(padding + 2));
            }
        }
        output.push_str(line.trim_end());
        output.push('\n');
    }

    output.trim_end().to_string()
}

/// Strip ANSI escape codes for length calculation
fn strip_ansi_codes(s: &str) -> String {
    let mut result = String::new();
    let mut in_escape = false;

    for c in s.chars() {
        if c == '\x1b' {
            in_escape = true;
        } else if in_escape {
            if c == 'm' {
                in_escape = false;
            }
        } else {
            result.push(c);
        }
    }

    result
}

/// Colorize a status string based on its category
pub fn colorize_status(status: &str) -> String {
    match status_category(status) {
        StatusCategory::Healthy => status.green().to_string(),
        StatusCategory::Warning => status.yellow().to_string(),
        StatusCategory::Error => status.red().to_string(),
        StatusCategory::Unknown => status.to_string(),
    }
}

/// Format resources as JSON
pub fn format_json<T: serde::Serialize>(resources: &[T], pretty: bool) -> Result<String, serde_json::Error> {
    if pretty {
        serde_json::to_string_pretty(resources)
    } else {
        serde_json::to_string(resources)
    }
}

/// Format resources as YAML
pub fn format_yaml<T: serde::Serialize>(resources: &[T]) -> Result<String, serde_yaml::Error> {
    serde_yaml::to_string(resources)
}

/// Format as just names
pub fn format_names<T: crate::resources::KubeResource>(resources: &[T]) -> String {
    resources
        .iter()
        .map(|r| {
            if let Some(ns) = r.namespace() {
                format!("{}/{}", ns, r.name())
            } else {
                r.name().to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}
