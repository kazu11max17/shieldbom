use axum::extract::{Path, Query, State};
use axum::Extension;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use shieldbom::models::AnalysisReport;

use super::AccountId;
use crate::errors::ApiError;
use crate::AppState;

#[derive(Serialize)]
pub struct ScanResponse {
    pub id: String,
    pub sbom_filename: String,
    pub format_detected: String,
    pub total_components: i64,
    pub total_vulns: i64,
    pub critical_count: i64,
    pub high_count: i64,
    pub medium_count: i64,
    pub low_count: i64,
    pub license_issues: i64,
    pub created_at: String,
}

#[derive(Serialize)]
pub struct ScanDetailResponse {
    #[serde(flatten)]
    pub scan: ScanResponse,
    pub report: AnalysisReport,
}

#[derive(Deserialize)]
pub struct ListParams {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

pub async fn create(
    State(state): State<AppState>,
    Extension(account): Extension<AccountId>,
    Json(report): Json<AnalysisReport>,
) -> Result<Json<ScanResponse>, ApiError> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let filename = report.sbom_file.display().to_string();
    let format = report.format_detected.to_string();
    let report_json = serde_json::to_string(&report)?;

    let db = state.db.lock().unwrap();
    db.execute(
        "INSERT INTO scans (id, account_id, sbom_filename, format_detected, total_components, total_vulns,
         critical_count, high_count, medium_count, low_count, license_issues, report_json, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        rusqlite::params![
            id,
            account.0,
            filename,
            format,
            report.stats.total_components as i64,
            report.stats.total_vulns as i64,
            report.stats.critical as i64,
            report.stats.high as i64,
            report.stats.medium as i64,
            report.stats.low as i64,
            report.stats.license_issues as i64,
            report_json,
            now,
        ],
    )?;

    Ok(Json(ScanResponse {
        id,
        sbom_filename: filename,
        format_detected: format,
        total_components: report.stats.total_components as i64,
        total_vulns: report.stats.total_vulns as i64,
        critical_count: report.stats.critical as i64,
        high_count: report.stats.high as i64,
        medium_count: report.stats.medium as i64,
        low_count: report.stats.low as i64,
        license_issues: report.stats.license_issues as i64,
        created_at: now,
    }))
}

pub async fn get_by_id(
    State(state): State<AppState>,
    Extension(account): Extension<AccountId>,
    Path(id): Path<String>,
) -> Result<Json<ScanDetailResponse>, ApiError> {
    let db = state.db.lock().unwrap();
    let mut stmt = db.prepare(
        "SELECT id, sbom_filename, format_detected, total_components, total_vulns,
         critical_count, high_count, medium_count, low_count, license_issues, report_json, created_at
         FROM scans WHERE id = ?1 AND account_id = ?2",
    )?;

    let result = stmt.query_row(rusqlite::params![id, account.0], |row| {
        let report_json: String = row.get(10)?;
        Ok((
            ScanResponse {
                id: row.get(0)?,
                sbom_filename: row.get(1)?,
                format_detected: row.get(2)?,
                total_components: row.get(3)?,
                total_vulns: row.get(4)?,
                critical_count: row.get(5)?,
                high_count: row.get(6)?,
                medium_count: row.get(7)?,
                low_count: row.get(8)?,
                license_issues: row.get(9)?,
                created_at: row.get(11)?,
            },
            report_json,
        ))
    });

    match result {
        Ok((scan, report_json)) => {
            let report: AnalysisReport = serde_json::from_str(&report_json)
                .map_err(|e| ApiError::Internal(e.to_string()))?;
            Ok(Json(ScanDetailResponse { scan, report }))
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            Err(ApiError::NotFound(format!("scan {id} not found")))
        }
        Err(e) => Err(ApiError::from(e)),
    }
}

pub async fn list(
    State(state): State<AppState>,
    Extension(account): Extension<AccountId>,
    Query(params): Query<ListParams>,
) -> Result<Json<Vec<ScanResponse>>, ApiError> {
    let limit = params.limit.unwrap_or(20).min(100);
    let offset = params.offset.unwrap_or(0);

    let db = state.db.lock().unwrap();
    let mut stmt = db.prepare(
        "SELECT id, sbom_filename, format_detected, total_components, total_vulns,
         critical_count, high_count, medium_count, low_count, license_issues, created_at
         FROM scans WHERE account_id = ?1 ORDER BY created_at DESC LIMIT ?2 OFFSET ?3",
    )?;

    let rows = stmt
        .query_map(rusqlite::params![account.0, limit, offset], |row| {
            Ok(ScanResponse {
                id: row.get(0)?,
                sbom_filename: row.get(1)?,
                format_detected: row.get(2)?,
                total_components: row.get(3)?,
                total_vulns: row.get(4)?,
                critical_count: row.get(5)?,
                high_count: row.get(6)?,
                medium_count: row.get(7)?,
                low_count: row.get(8)?,
                license_issues: row.get(9)?,
                created_at: row.get(10)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Json(rows))
}
