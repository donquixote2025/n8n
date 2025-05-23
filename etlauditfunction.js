/**
 * ETL Audit Function (Standalone Module)
 * Tujuan: Mengaudit, menilai, memonitor, dan mendokumentasikan proses maupun output data dari etlcombinationkpi.js.
 * Output: Audit komprehensif, validasi metrik, diagnosa error/anomali, serta dokumentasi file/data (file, size_bytes, modified_utc, created_utc, sha256, abs_path).
 * Endpoint dapat dipisah (misal: /etl_audit) dan dipanggil untuk mengaudit hasil etlcombinationkpi.js.
 */

const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

// === UTILITY ===
function avg(arr) {
  if (!arr.length) return 0;
  const valid = arr.filter(x => typeof x === "number" && !isNaN(x));
  return valid.length ? valid.reduce((a, b) => a + b, 0) / valid.length : 0;
}

// === DATA QUALITY CLASSIFICATION ===
function classifyDataQuality({
  avg_completeness_etl,
  avg_confidence_score_etl,
  avg_completeness_audit,
  avg_confidence_score_audit,
  data_quality_score,
  completeness_gap,
  confidence_gap
}) {
  const normCompGap = Math.min(Math.abs(completeness_gap) / 12, 1);
  const normConfGap = Math.min(Math.abs(confidence_gap) / 0.12, 1);

  const normCompletenessEtl = Math.max(0, Math.min(1, avg_completeness_etl / 100));
  const normConfEtl = Math.max(0, Math.min(1, avg_confidence_score_etl));
  const normCompletenessAudit = Math.max(0, Math.min(1, avg_completeness_audit / 100));
  const normConfAudit = Math.max(0, Math.min(1, avg_confidence_score_audit));
  const normDqScore = Math.max(0, Math.min(1, data_quality_score / 100));

  const score =
    normCompletenessEtl * 18 +
    normConfEtl * 14 +
    normCompletenessAudit * 18 +
    normConfAudit * 14 +
    normDqScore * 30 -
    normCompGap * 3 -
    normConfGap * 3;

  let classification = "very bad";
  if (score >= 91) classification = "excellent";
  else if (score >= 81) classification = "very good";
  else if (score >= 66) classification = "good";
  else if (score >= 51) classification = "bad";
  return {
    data_classification: classification,
    data_classification_score: Math.round(score * 10) / 10
  };
}

// === FILE DOCUMENTATION LOGIC ===
function getFileAuditInfo(targetFile) {
  try {
    const stat = fs.statSync(targetFile);
    const sha256 = crypto.createHash('sha256').update(fs.readFileSync(targetFile)).digest('hex');
    return {
      file: path.basename(targetFile),
      size_bytes: stat.size,
      modified_utc: new Date(stat.mtimeMs).toISOString(),
      created_utc: new Date(stat.ctimeMs).toISOString(),
      sha256,
      abs_path: path.resolve(targetFile)
    };
  } catch (err) {
    return { file: targetFile, error: err.message };
  }
}

// === ETL AUDIT FUNCTION ===
function etlAuditFunction(etlItems, auditConfig = {}) {
  // etlItems: output dari etlcombinationkpi.js (array of row objects)
  // auditConfig: { source_file (optional) }

  const auditLog = [];
  const missingCritical = [];
  const anomalyItems = [];
  const anomalyReasons = [];
  const completenessScoresETL = [];
  const confidenceScoresETL = [];
  const completenessScoresAudit = [];
  const confidenceScoresAudit = [];
  const embeddingCounts = {};
  const fieldCoverage = {};
  const divisionCount = {};
  const dataSourceSet = new Set();
  const contentSample = [];

  // === Komponen Audit ===
  function completenessScoreAudit(data) {
    // Hitung proporsi field yang tidak null/undefined/NaN
    let keys = Object.keys(data).filter(k => !["embedding", "error_flags", "sources_included"].includes(k));
    let filled = 0, total = 0;
    for (const k of keys) {
      if (data[k] !== null && data[k] !== undefined && !Number.isNaN(data[k])) filled++;
      total++;
    }
    return total === 0 ? 100 : Math.round((filled / total) * 10000) / 100;
  }
  function confidenceScoreAudit(data) {
    let keys = Object.keys(data).filter(k => !["embedding", "error_flags", "sources_included"].includes(k));
    let valid = 0, total = 0;
    for (const k of keys) {
      const v = data[k];
      if (v !== null && v !== undefined && !Number.isNaN(v)) valid++;
      total++;
    }
    return total === 0 ? 1 : Math.round((valid / total) * 1000) / 1000;
  }

  for (const item of etlItems) {
    const data = item.json ? item.json : item;
    // ETL dari upstream
    let etlCompleteness = (typeof data.completeness_score === "number") ? data.completeness_score : 0;
    let etlConfidence = (typeof data.confidence_score === "number") ? data.confidence_score : 0;
    completenessScoresETL.push(etlCompleteness);
    confidenceScoresETL.push(etlConfidence);

    // AUDIT (independen dari ETL)
    let auditCompleteness = completenessScoreAudit(data);
    let auditConfidence = confidenceScoreAudit(data);
    completenessScoresAudit.push(auditCompleteness);
    confidenceScoresAudit.push(auditConfidence);

    // Error & Critical
    if (data.error_flags && data.error_flags.length > 0) {
      auditLog.push({
        item_number: data.item_number,
        id: data.id,
        error_flags: data.error_flags
      });
      missingCritical.push(data);
    }

    // Anomaly Detection
    let localAnomalyReason = [];
    if (typeof data.confidence_score === "number" && data.confidence_score < 0.5) {
      if (data.completeness_score !== undefined && data.completeness_score < 60) {
        localAnomalyReason.push("Completeness score sangat rendah");
      }
      if (data.embedding && Array.isArray(data.embedding) && data.embedding.length > 10) {
        localAnomalyReason.push("Terlalu banyak field penting yang kosong/missing");
      }
      if (typeof data.completeness_score === "number" && typeof data.confidence_score === "number" &&
          data.completeness_score > 70 && data.confidence_score < 0.5) {
        localAnomalyReason.push("Nilai completeness tinggi tapi confidence rendah, ada kemungkinan data outlier/inkonsisten");
      }
      if (data.error_flags && data.error_flags.length > 0) {
        localAnomalyReason.push("Critical error flag terdeteksi pada data");
      }
      const reasonText = localAnomalyReason.length > 0 ? localAnomalyReason.join("; ") : "Confidence rendah, data perlu investigasi lanjutan";
      anomalyItems.push({
        item_number: data.item_number,
        id: data.id,
        confidence_score: data.confidence_score,
        anomaly_reason: reasonText
      });
      anomalyReasons.push(reasonText);
    }

    // Field coverage
    Object.keys(data).forEach(f => {
      if (!(f in fieldCoverage)) fieldCoverage[f] = 0;
      if (data[f] !== null && data[f] !== undefined && data[f] !== "") fieldCoverage[f]++;
    });

    // Division stats & sources
    if (Array.isArray(data.sources_included)) {
      data.sources_included.forEach(div => {
        if (!(div in divisionCount)) divisionCount[div] = 0;
        divisionCount[div]++;
        dataSourceSet.add(div);
      });
    }

    // Embedding mode
    if (Array.isArray(data.embedding)) {
      data.embedding.forEach(field => {
        if (!(field in embeddingCounts)) embeddingCounts[field] = 0;
        embeddingCounts[field]++;
      });
    }

    // Sample content
    if (contentSample.length < 3) {
      contentSample.push({
        id: data.id,
        department: data.department,
        sources_included: data.sources_included,
        completeness_score: data.completeness_score,
        confidence_score: data.confidence_score,
        fields: Object.keys(data).length
      });
    }
  }

  // === Monitoring summary (ETL & AUDIT) ===
  const avgCompletenessETL = avg(completenessScoresETL);
  const avgConfidenceETL = avg(confidenceScoresETL);
  const avgCompletenessAudit = avg(completenessScoresAudit);
  const avgConfidenceAudit = avg(confidenceScoresAudit);

  // === GAP ===
  const completenessGap = Math.abs(avgCompletenessETL - avgCompletenessAudit);
  const confidenceGap = Math.abs(avgConfidenceETL - avgConfidenceAudit);

  // === Embedding mode: top 10 ===
  const embedding_mode = Object.entries(embeddingCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([field, count]) => ({ field, count }));

  // === DATA QUALITY SCORE ===
  const countItems = etlItems.length || 1;
  const maxMissingCritical = Math.max(1, Math.round(0.05 * countItems));
  const maxAnomaly = Math.max(1, Math.round(0.05 * countItems));
  const completenessNorm = Math.max(0, Math.min(1, avgCompletenessAudit / 100));
  const confidenceNorm = Math.max(0, Math.min(1, avgConfidenceAudit));
  const missingCriticalNorm = 1 - Math.min(1, missingCritical.length / maxMissingCritical);
  const anomalyNorm = 1 - Math.min(1, anomalyItems.length / maxAnomaly);
  const embeddingNorm = 1 - Math.min(1, (embedding_mode.length > 0 ? embedding_mode[0].count : 0) / (countItems * 0.8));
  let gapPenalty = 0;
  if (completenessGap > 5) gapPenalty += 0.05;
  if (confidenceGap > 0.05) gapPenalty += 0.05;

  const dataQualityScoreRaw =
    0.4 * completenessNorm +
    0.3 * confidenceNorm +
    0.2 * (0.5 * missingCriticalNorm + 0.5 * anomalyNorm) +
    0.1 * embeddingNorm - gapPenalty;

  const dataQualityScore = Math.max(0, Math.min(100, Math.round(dataQualityScoreRaw * 100)));

  // === DATA CLASSIFICATION ===
  const classificationObj = classifyDataQuality({
    avg_completeness_etl: avgCompletenessETL,
    avg_confidence_score_etl: avgConfidenceETL,
    avg_completeness_audit: avgCompletenessAudit,
    avg_confidence_score_audit: avgConfidenceAudit,
    data_quality_score: dataQualityScore,
    completeness_gap: completenessGap,
    confidence_gap: confidenceGap
  });

  // === DATA TRACING ===
  let dataTracing = "";
  if (dataQualityScore < 70) {
    const issues = [];
    if (completenessNorm < 0.75) issues.push("Rata-rata completeness rendah");
    if (confidenceNorm < 0.75) issues.push("Confidence score rata-rata rendah");
    if (missingCritical.length > maxMissingCritical) issues.push("Terlalu banyak item critical field hilang");
    if (anomalyItems.length > maxAnomaly) issues.push("Banyak data anomaly (confidence rendah)");
    if (embedding_mode.length > 0 && embedding_mode[0].count > countItems * 0.5) issues.push(`Field '${embedding_mode[0].field}' sering tidak lengkap`);
    if (Object.keys(divisionCount).length < 3) issues.push("Data tidak merata antar divisi");
    if (issues.length === 0) {
      dataTracing = "Data quality score buruk namun tidak terdeteksi masalah spesifik, cek proses ETL lebih lanjut.";
    } else {
      dataTracing = "Masalah teridentifikasi: " + issues.join("; ");
    }
  } else {
    dataTracing = "";
  }

  // === File Documentation (if file is provided) ===
  let file_docs = [];
  if (auditConfig && auditConfig.source_file) {
    const files = Array.isArray(auditConfig.source_file) ? auditConfig.source_file : [auditConfig.source_file];
    file_docs = files.map(getFileAuditInfo);
  }

  // === Output Result ===
  const result = Object.assign(
    { id: "etl_audit_" + Date.now() + "_" + Math.floor(Math.random() * 1000000) },
    {
      count_output: etlItems.length,
      avg_completeness_etl: avgCompletenessETL,
      avg_confidence_score_etl: avgConfidenceETL,
      avg_completeness_audit: avgCompletenessAudit,
      avg_confidence_score_audit: avgConfidenceAudit,
      data_quality_score: dataQualityScore,
      completeness_gap: completenessGap,
      confidence_gap: confidenceGap,
      data_classification: classificationObj.data_classification,
      data_classification_score: classificationObj.data_classification_score,
      data_tracing: dataTracing,
      anomaly_reason: anomalyReasons.slice(0, 5), // alasan utama anomali
      audit_log: auditLog,
      file_documentation: file_docs, // Dokumentasi file sumber
      metadata: {
        data_source: Array.from(dataSourceSet),
        sample_content: contentSample,
        field_coverage: fieldCoverage,
        division_count: divisionCount
      }
    }
  );

  return result;
}

module.exports = { etlAuditFunction };
