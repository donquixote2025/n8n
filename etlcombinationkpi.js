// Advanced Multi-Join ETL: Data Master KPI 6 Divisi (Finance, Sales/Marketing, HR, Operation, Project, Strategic)
// Output siap untuk data warehouse, dashboard, & analitik lintas divisi (presisi, akurat, minim null, multirow, multi-join, flag impute, outlier detection, confidence scoring, completeness scoring).

const FIELDS_BY_DIV = {
  hr: [
    "employee_id", "employee_name", "hire_date", "termination_date", "gender", "age", "job_level",
    "is_promoted", "is_high_performer", "absent_days", "training_hours", "ess_score", "salary", "market_salary",
    "compensation_ratio", "date_of_birth", "marital_status", "education_level", "employment_status",
    "employment_type", "position_title", "supervisor_id", "years_in_company", "performance_rating",
    "leave_days", "leave_type", "leave_balance", "training_count", "certification_count", "engagement_score",
    "bonus", "accident_count", "reason_for_leaving", "union_member", "disciplinary_action_count"
  ],
  finance: [
    "fiscal_year", "budget_month", "budget_allocated", "actual_spending", "forecast_budget", "forecast_spending",
    "forecast_revenue", "forecast_profit", "current_assets", "current_liabilities", "quick_assets", "inventory",
    "total_assets", "total_liabilities", "total_equity", "cash_and_cash_equivalents", "accounts_receivable",
    "accounts_payable", "short_term_debt", "long_term_debt", "total_revenue", "cost_of_goods_sold", "gross_profit",
    "operating_income", "operating_expenses", "net_profit", "ebit", "ebitda", "depreciation", "amortization",
    "interest_expense", "tax_expense", "operating_cash_flow", "investing_cash_flow", "financing_cash_flow",
    "capital_expenditure"
  ],
  sales: [
    "sales_target", "actual_sales", "new_customers", "customer_retention_rate", "conversion_rate",
    "avg_transaction_value", "marketing_spending", "campaign_count", "leads_generated", "units_sold",
    "transaction_count", "product_id", "channel", "campaign_id", "gross_sales", "discount_amount",
    "sales_return_value", "sales_return_count", "refund_value", "refund_count", "online_sales", "offline_sales",
    "impressions", "clicks"
  ],
  op: [
    "operational_cost", "order_fulfillment_rate", "stockout_rate", "shrinkage_rate", "customer_complaint_count",
    "avg_delivery_time", "asset_utilization", "maintenance_cost", "uptime_percentage", "average_inventory",
    "beginning_inventory", "ending_inventory", "items_received", "items_shipped", "items_damaged", "order_volume",
    "employee_count_on_shift", "labor_hours", "energy_consumption", "maintenance_ticket_count", "asset_downtime",
    "customer_return_count", "backorder_count"
  ],
  project: [
    "project_id","project_name","project_manager","start_date","end_date","project_status","project_budget","actual_cost",
    "planned_roi","actual_roi","issue_count","task_completion_rate","stakeholder_satisfaction","project_type","project_priority",
    "project_phase","methodology","planned_end_date","baseline_end_date","committed_cost","forecast_cost","extension_count",
    "change_request_count","risk_count","resource_allocated_fte","resource_utilization_rate"
  ],
  strategic: [
    "strategy_id","strategy_name","owner","owner_position","board_sponsor","strategy_status","planned_end_date","strategy_category",
    "strategy_type","alignment_with_corporate","alignment_with_okr","strategic_kpi_target","strategic_kpi_actual","kpi_unit",
    "kpi_frequency","risk_level","risk_description","main_risk_owner","mitigation_plan_available","initiative_count",
    "initiative_success_rate","initiative_on_track_count","initiative_delayed_count","initiative_completed_count",
    "initiative_budget_total","initiative_budget_used","board_satisfaction","stakeholder_feedback_score","last_review_date",
    "resource_allocated_fte","resource_utilization_rate","expected_benefit_value","realized_benefit_value"
  ]
};

function cleanString(str) {
  return (typeof str === 'string' ? str.trim().replace(/\s+/g, ' ') : str);
}
function toNumber(val) {
  return (val === undefined || val === null || val === '' ? null : Number(val));
}
function toDate(val) {
  if (!val || val === '') return null;
  const d = new Date(val);
  return isNaN(d.getTime()) ? null : d.toISOString().slice(0, 10);
}
function isValidNumber(v) {
  return typeof v === 'number' && !isNaN(v);
}
function mean(arr) {
  return arr.length ? arr.reduce((a,b) => a + b, 0) / arr.length : null;
}
function sum(arr) {
  return arr.length ? arr.reduce((a,b) => a + b, 0) : null;
}
function median(arr) {
  if (!arr.length) return null;
  const s = arr.slice().sort((a,b) => a-b);
  const mid = Math.floor(s.length/2);
  return s.length % 2 === 0 ? (s[mid-1]+s[mid])/2 : s[mid];
}
function mode(arr) {
  if (!arr.length) return null;
  const freq = {};
  arr.forEach(v => { freq[v] = (freq[v]||0)+1; });
  let max = 0, res = arr[0];
  Object.entries(freq).forEach(([v, cnt]) => { if (cnt>max) { max=cnt; res=Number(v);} });
  return res;
}
function detectOutlier(arr, field) {
  // Deteksi outlier sederhana: Z-score > 3 atau < -3
  const vals = arr.map(r => toNumber(r[field])).filter(isValidNumber);
  if (vals.length < 3) return [];
  const mu = mean(vals), sd = Math.sqrt(mean(vals.map(v => Math.pow(v-mu,2))));
  return arr.map((r,i) => {
    const v = toNumber(r[field]);
    if (!isValidNumber(v)) return false;
    const z = sd ? (v-mu)/sd : 0;
    return Math.abs(z) > 3;
  });
}
function mergeRowsByKey(arraysPerDivisi) {
  const merged = {};
  arraysPerDivisi.forEach(rows => {
    if (rows && rows.length) {
      rows.forEach(row => {
        Object.entries(row).forEach(([k, v]) => {
          if (v !== null && v !== undefined && v !== "" && !(k in merged)) {
            merged[k] = v;
          }
        });
      });
    }
  });
  return merged;
}
function parseIdToDivision(id) {
  if (!id) return [];
  const div = [];
  if (/hr|emp|employee|E\d+/i.test(id)) div.push("hr");
  if (/fin|finance|fiscal|budget/i.test(id)) div.push("finance");
  if (/sales|marketing|S\d+/i.test(id)) div.push("sales");
  if (/operation|op|O\d+/i.test(id)) div.push("op");
  if (/project|proj|P\d+/i.test(id)) div.push("project");
  if (/strategic|strategy|STR/i.test(id)) div.push("strategic");
  if (/^sales|^marketing/i.test(id)) div.push("sales");
  if (/^finance|^fiscal/i.test(id)) div.push("finance");
  if (/^hr|^employee/i.test(id)) div.push("hr");
  if (/^operation/i.test(id)) div.push("op");
  if (/^project/i.test(id)) div.push("project");
  if (/^strategic|^strategy/i.test(id)) div.push("strategic");
  if (div.length === 0) div.push("hr","finance","sales","op","project","strategic");
  return Array.from(new Set(div));
}
function computeCompletenessById(obj, id) {
  const divs = parseIdToDivision(id);
  let relevantFields = [];
  divs.forEach(div => {
    relevantFields = relevantFields.concat(FIELDS_BY_DIV[div] || []);
  });
  relevantFields = Array.from(new Set(relevantFields));
  let filled = 0;
  const missing = [];
  relevantFields.forEach(f => {
    const v = obj[f];
    if (v === null || v === undefined || v === "" || (typeof v === "number" && !isValidNumber(v))) {
      missing.push(f);
    } else if (typeof v === "number" && v === 0 && !['compensation_ratio','conversion_rate','customer_retention_rate','market_salary','salary','avg_transaction_value'].includes(f)) {
      missing.push(f);
    } else {
      filled++;
    }
  });
  const completeness = relevantFields.length ? filled / relevantFields.length : 1;
  return {
    completeness_score: Math.round(completeness * 1000) / 10,
    missing_fields: missing
  };
}
function confidenceScore(obj, completeness_score, missing_fields) {
  let conf = 1.0;
  if (completeness_score < 60) conf *= 0.5;
  else if (completeness_score < 80) conf *= 0.7;
  else if (completeness_score < 95) conf *= 0.9;
  if (missing_fields.length > 20) conf *= 0.7;
  else if (missing_fields.length > 10) conf *= 0.85;
  else conf *= 0.9;
  if (completeness_score < 70) conf *= 0.7;
  else conf *= 0.95;
  if (missing_fields.length > 30) conf *= 0.6;
  let anomaly = 0;
  Object.values(obj).forEach(v => {
    if (typeof v === "number" && (!isFinite(v) || isNaN(v) || v < 0 && Math.abs(v) > 999999999)) anomaly++;
  });
  if (anomaly > 2) conf *= 0.7;
  conf = Math.max(0, Math.min(1, +conf.toFixed(3)));
  return conf;
}

const sumFields = [
  'units_sold','transaction_count','campaign_count','leads_generated','new_customers','impressions','clicks',
  'items_received','items_shipped','items_damaged','order_volume','employee_count_on_shift','labor_hours','energy_consumption','maintenance_ticket_count','customer_return_count','backorder_count',
];

function etlCombinationKPI(items) {
  const hr = [], finance = [], salesMarketing = [], operation = [], project = [], strategic = [];
  for (const itm of items) {
    const row = itm.json ? itm.json : itm;
    if ('employee_id' in row && row.employee_id) hr.push(row);
    else if ('fiscal_year' in row && row.fiscal_year) finance.push(row);
    else if ('sales_target' in row && row.sales_target) salesMarketing.push(row);
    else if ('operational_cost' in row && row.operational_cost) operation.push(row);
    else if ('project_id' in row && row.project_id) project.push(row);
    else if ('strategy_id' in row && row.strategy_id) strategic.push(row);
  }
  function getKey(row) {
    const dep = cleanString(row.department || row.department_name || "");
    const reg = cleanString(row.region || "");
    const store = cleanString(row.store_id || "");
    let month = null;
    if ('budget_month' in row && row.budget_month != null) month = toNumber(row.budget_month);
    else if ('month' in row && row.month != null) month = toNumber(row.month);
    else if ('fiscal_year' in row && row.fiscal_year) month = 1;
    else month = 1;
    return `${dep}|${reg}|${store}|${month}`;
  }
  const allKeys = [
    ...hr.map(getKey),
    ...finance.map(getKey),
    ...salesMarketing.map(getKey),
    ...operation.map(getKey),
    ...project.map(getKey),
    ...strategic.map(getKey)
  ];
  const keySet = new Set(allKeys);
  function buildMultiIndex(arr) {
    const idx = {};
    arr.forEach(row => {
      const key = getKey(row);
      if (!idx[key]) idx[key] = [];
      idx[key].push(row);
    });
    return idx;
  }
  const hrIdx = buildMultiIndex(hr);
  const financeIdx = buildMultiIndex(finance);
  const salesIdx = buildMultiIndex(salesMarketing);
  const opIdx = buildMultiIndex(operation);
  const projIdx = buildMultiIndex(project);
  const stratIdx = buildMultiIndex(strategic);

  function buildFallbackStat(arr, field) {
    const nums = arr.map(r => toNumber(r[field])).filter(isValidNumber);
    return { mean: mean(nums), median: median(nums), mode: mode(nums) };
  }
  // Build fallbackStats dinamis agar extensible
  const fallbackStats = {};
  Object.entries(FIELDS_BY_DIV).forEach(([div, fields]) => {
    fallbackStats[div] = {};
    fields.forEach(f => {
      let arr = [];
      if (div === 'hr') arr = hr;
      else if (div === 'finance') arr = finance;
      else if (div === 'sales') arr = salesMarketing;
      else if (div === 'op') arr = operation;
      else if (div === 'project') arr = project;
      else if (div === 'strategic') arr = strategic;
      fallbackStats[div][f] = buildFallbackStat(arr, f);
    });
  });

  // === OUTPUT OBJECT, multi-join enrichment: gunakan mergedRow dan aggrField
  function aggrField(field, mergedRow, arr, fallbackStat, aggrFn) {
    if (isValidNumber(toNumber(mergedRow[field]))) return toNumber(mergedRow[field]);
    let vals = arr.map(r => toNumber(r[field])).filter(isValidNumber);
    if (!aggrFn) aggrFn = sumFields.includes(field) ? sum : mean;
    if (vals.length) return aggrFn(vals);
    if (fallbackStat && isValidNumber(fallbackStat.mean)) return fallbackStat.mean;
    return null;
  }

  const output = [];
  let itemNumber = 1;
  for (const key of keySet) {
    const [dep, reg, store, month] = key.split('|');
    const hrRows = hrIdx[key] || [], financeRows = financeIdx[key] || [], salesRows = salesIdx[key] || [],
          opRows = opIdx[key] || [], projRows = projIdx[key] || [], stratRows = stratIdx[key] || [];
    const mergedRow = mergeRowsByKey([hrRows, financeRows, salesRows, opRows, projRows, stratRows]);
    const rowId = mergedRow.employee_id
      ? `${dep}_${reg}_${store}_${month}_${cleanString(mergedRow.employee_id)}`
      : `${dep}_${reg}_${store}_${month}_0`;

    // === 2. LINEAGE METADATA: sumber data/divisi per item
    const sources_included = [];
    if (hrRows.length) sources_included.push("HR");
    if (financeRows.length) sources_included.push("Finance");
    if (salesRows.length) sources_included.push("Sales");
    if (opRows.length) sources_included.push("Operation");
    if (projRows.length) sources_included.push("Project");
    if (stratRows.length) sources_included.push("Strategic");

    // === 1. CONFIGURABILITY & 4. EXTENSIBILITY: mapping field dinamis, meta config
    const config_info = {
      fields_by_div: Object.keys(FIELDS_BY_DIV),
      field_count: Object.values(FIELDS_BY_DIV).reduce((a, b) => a + b.length, 0)
    };

    // === 3. ERROR HANDLING MINIMAL: flag jika field critical hilang/null, simpan di kolom error_flags
    const error_flags = [];
    if (!mergedRow.employee_id && !mergedRow.fiscal_year && !mergedRow.sales_target && !mergedRow.operational_cost && !mergedRow.project_id && !mergedRow.strategy_id) {
      error_flags.push('No primary key fields present');
    }

    // ========== Tambahan: Outlier & Imputed Flags, seperti agentETLAdvanced ==========
    // Outlier flags
    const outlier_flags = {};
    Object.entries(FIELDS_BY_DIV).forEach(([div, fields]) => {
      fields.forEach(f => {
        const arr = div==='hr'?hr:div==='finance'?finance:div==='sales'?salesMarketing:div==='op'?operation:div==='project'?project:strategic;
        const outliers = detectOutlier(arr, f);
        if (outliers.length) {
          const idx = arr.findIndex(r => r === mergedRow);
          if (idx >= 0 && outliers[idx]) outlier_flags[f] = true;
        }
      });
    });

    // Imputed flags
    const imputed_flags = {};
    Object.entries(mergedRow).forEach(([k,v]) => {
      if (v === null || v === undefined || v === "") imputed_flags[k] = true;
    });

    // ========== END Tambahan Advanced ==========
    // OUTPUT OBJECT
    const obj = {
      item_number: itemNumber,
      id: rowId,
      sources_included,
      config_info,
      error_flags,
      department: dep, region: reg, store_id: store, month: toNumber(month),
      // FINANCE
      fiscal_year: aggrField('fiscal_year', mergedRow, financeRows, fallbackStats.finance.fiscal_year),
      budget_month: aggrField('budget_month', mergedRow, financeRows, fallbackStats.finance.budget_month),
      budget_allocated: aggrField('budget_allocated', mergedRow, financeRows, fallbackStats.finance.budget_allocated),
      actual_spending: aggrField('actual_spending', mergedRow, financeRows, fallbackStats.finance.actual_spending),
      forecast_budget: aggrField('forecast_budget', mergedRow, financeRows, fallbackStats.finance.forecast_budget),
      forecast_spending: aggrField('forecast_spending', mergedRow, financeRows, fallbackStats.finance.forecast_spending),
      forecast_revenue: aggrField('forecast_revenue', mergedRow, financeRows, fallbackStats.finance.forecast_revenue),
      forecast_profit: aggrField('forecast_profit', mergedRow, financeRows, fallbackStats.finance.forecast_profit),
      current_assets: aggrField('current_assets', mergedRow, financeRows, fallbackStats.finance.current_assets),
      current_liabilities: aggrField('current_liabilities', mergedRow, financeRows, fallbackStats.finance.current_liabilities),
      quick_assets: aggrField('quick_assets', mergedRow, financeRows, fallbackStats.finance.quick_assets),
      inventory: aggrField('inventory', mergedRow, financeRows, fallbackStats.finance.inventory),
      total_assets: aggrField('total_assets', mergedRow, financeRows, fallbackStats.finance.total_assets),
      total_liabilities: aggrField('total_liabilities', mergedRow, financeRows, fallbackStats.finance.total_liabilities),
      total_equity: aggrField('total_equity', mergedRow, financeRows, fallbackStats.finance.total_equity),
      cash_and_cash_equivalents: aggrField('cash_and_cash_equivalents', mergedRow, financeRows, fallbackStats.finance.cash_and_cash_equivalents),
      accounts_receivable: aggrField('accounts_receivable', mergedRow, financeRows, fallbackStats.finance.accounts_receivable),
      accounts_payable: aggrField('accounts_payable', mergedRow, financeRows, fallbackStats.finance.accounts_payable),
      short_term_debt: aggrField('short_term_debt', mergedRow, financeRows, fallbackStats.finance.short_term_debt),
      long_term_debt: aggrField('long_term_debt', mergedRow, financeRows, fallbackStats.finance.long_term_debt),
      total_revenue: aggrField('total_revenue', mergedRow, financeRows, fallbackStats.finance.total_revenue),
      cost_of_goods_sold: aggrField('cost_of_goods_sold', mergedRow, financeRows, fallbackStats.finance.cost_of_goods_sold),
      gross_profit: aggrField('gross_profit', mergedRow, financeRows, fallbackStats.finance.gross_profit),
      operating_income: aggrField('operating_income', mergedRow, financeRows, fallbackStats.finance.operating_income),
      operating_expenses: aggrField('operating_expenses', mergedRow, financeRows, fallbackStats.finance.operating_expenses),
      net_profit: aggrField('net_profit', mergedRow, financeRows, fallbackStats.finance.net_profit),
      ebit: aggrField('ebit', mergedRow, financeRows, fallbackStats.finance.ebit),
      ebitda: aggrField('ebitda', mergedRow, financeRows, fallbackStats.finance.ebitda),
      depreciation: aggrField('depreciation', mergedRow, financeRows, fallbackStats.finance.depreciation),
      amortization: aggrField('amortization', mergedRow, financeRows, fallbackStats.finance.amortization),
      interest_expense: aggrField('interest_expense', mergedRow, financeRows, fallbackStats.finance.interest_expense),
      tax_expense: aggrField('tax_expense', mergedRow, financeRows, fallbackStats.finance.tax_expense),
      operating_cash_flow: aggrField('operating_cash_flow', mergedRow, financeRows, fallbackStats.finance.operating_cash_flow),
      investing_cash_flow: aggrField('investing_cash_flow', mergedRow, financeRows, fallbackStats.finance.investing_cash_flow),
      financing_cash_flow: aggrField('financing_cash_flow', mergedRow, financeRows, fallbackStats.finance.financing_cash_flow),
      capital_expenditure: aggrField('capital_expenditure', mergedRow, financeRows, fallbackStats.finance.capital_expenditure),
      // HR
      employee_id: cleanString(mergedRow.employee_id),
      employee_name: cleanString(mergedRow.employee_name),
      hire_date: toDate(mergedRow.hire_date),
      termination_date: toDate(mergedRow.termination_date),
      gender: cleanString(mergedRow.gender),
      age: aggrField('age', mergedRow, hrRows, fallbackStats.hr.age),
      job_level: cleanString(mergedRow.job_level),
      is_promoted: cleanString(mergedRow.is_promoted),
      is_high_performer: cleanString(mergedRow.is_high_performer),
      absent_days: aggrField('absent_days', mergedRow, hrRows, fallbackStats.hr.absent_days),
      training_hours: aggrField('training_hours', mergedRow, hrRows, fallbackStats.hr.training_hours),
      ess_score: aggrField('ess_score', mergedRow, hrRows, fallbackStats.hr.ess_score),
      salary: aggrField('salary', mergedRow, hrRows, fallbackStats.hr.salary),
      market_salary: aggrField('market_salary', mergedRow, hrRows, fallbackStats.hr.market_salary),
      compensation_ratio: aggrField('compensation_ratio', mergedRow, hrRows, fallbackStats.hr.compensation_ratio),
      date_of_birth: toDate(mergedRow.date_of_birth),
      marital_status: cleanString(mergedRow.marital_status),
      education_level: cleanString(mergedRow.education_level),
      employment_status: cleanString(mergedRow.employment_status),
      employment_type: cleanString(mergedRow.employment_type),
      position_title: cleanString(mergedRow.position_title),
      supervisor_id: cleanString(mergedRow.supervisor_id),
      years_in_company: aggrField('years_in_company', mergedRow, hrRows, fallbackStats.hr.years_in_company),
      performance_rating: aggrField('performance_rating', mergedRow, hrRows, fallbackStats.hr.performance_rating),
      leave_days: aggrField('leave_days', mergedRow, hrRows, fallbackStats.hr.leave_days),
      leave_type: cleanString(mergedRow.leave_type),
      leave_balance: aggrField('leave_balance', mergedRow, hrRows, fallbackStats.hr.leave_balance),
      training_count: aggrField('training_count', mergedRow, hrRows, fallbackStats.hr.training_count),
      certification_count: aggrField('certification_count', mergedRow, hrRows, fallbackStats.hr.certification_count),
      engagement_score: aggrField('engagement_score', mergedRow, hrRows, fallbackStats.hr.engagement_score),
      bonus: aggrField('bonus', mergedRow, hrRows, fallbackStats.hr.bonus),
      accident_count: aggrField('accident_count', mergedRow, hrRows, fallbackStats.hr.accident_count),
      reason_for_leaving: cleanString(mergedRow.reason_for_leaving),
      union_member: cleanString(mergedRow.union_member),
      disciplinary_action_count: aggrField('disciplinary_action_count', mergedRow, hrRows, fallbackStats.hr.disciplinary_action_count),
      // SALES/MARKETING
      sales_target: aggrField('sales_target', mergedRow, salesRows, fallbackStats.sales.sales_target),
      actual_sales: aggrField('actual_sales', mergedRow, salesRows, fallbackStats.sales.actual_sales),
      new_customers: aggrField('new_customers', mergedRow, salesRows, fallbackStats.sales.new_customers),
      customer_retention_rate: aggrField('customer_retention_rate', mergedRow, salesRows, fallbackStats.sales.customer_retention_rate),
      conversion_rate: aggrField('conversion_rate', mergedRow, salesRows, fallbackStats.sales.conversion_rate),
      avg_transaction_value: aggrField('avg_transaction_value', mergedRow, salesRows, fallbackStats.sales.avg_transaction_value),
      marketing_spending: aggrField('marketing_spending', mergedRow, salesRows, fallbackStats.sales.marketing_spending),
      campaign_count: aggrField('campaign_count', mergedRow, salesRows, fallbackStats.sales.campaign_count),
      leads_generated: aggrField('leads_generated', mergedRow, salesRows, fallbackStats.sales.leads_generated),
      units_sold: aggrField('units_sold', mergedRow, salesRows, fallbackStats.sales.units_sold),
      transaction_count: aggrField('transaction_count', mergedRow, salesRows, fallbackStats.sales.transaction_count),
      product_id: cleanString(mergedRow.product_id),
      channel: cleanString(mergedRow.channel),
      campaign_id: cleanString(mergedRow.campaign_id),
      gross_sales: aggrField('gross_sales', mergedRow, salesRows, fallbackStats.sales.gross_sales),
      discount_amount: aggrField('discount_amount', mergedRow, salesRows, fallbackStats.sales.discount_amount),
      sales_return_value: aggrField('sales_return_value', mergedRow, salesRows, fallbackStats.sales.sales_return_value),
      sales_return_count: aggrField('sales_return_count', mergedRow, salesRows, fallbackStats.sales.sales_return_count),
      refund_value: aggrField('refund_value', mergedRow, salesRows, fallbackStats.sales.refund_value),
      refund_count: aggrField('refund_count', mergedRow, salesRows, fallbackStats.sales.refund_count),
      online_sales: aggrField('online_sales', mergedRow, salesRows, fallbackStats.sales.online_sales),
      offline_sales: aggrField('offline_sales', mergedRow, salesRows, fallbackStats.sales.offline_sales),
      impressions: aggrField('impressions', mergedRow, salesRows, fallbackStats.sales.impressions),
      clicks: aggrField('clicks', mergedRow, salesRows, fallbackStats.sales.clicks),
      // OPERATION
      operational_cost: aggrField('operational_cost', mergedRow, opRows, fallbackStats.op.operational_cost),
      order_fulfillment_rate: aggrField('order_fulfillment_rate', mergedRow, opRows, fallbackStats.op.order_fulfillment_rate),
      stockout_rate: aggrField('stockout_rate', mergedRow, opRows, fallbackStats.op.stockout_rate),
      shrinkage_rate: aggrField('shrinkage_rate', mergedRow, opRows, fallbackStats.op.shrinkage_rate),
      customer_complaint_count: aggrField('customer_complaint_count', mergedRow, opRows, fallbackStats.op.customer_complaint_count),
      avg_delivery_time: aggrField('avg_delivery_time', mergedRow, opRows, fallbackStats.op.avg_delivery_time),
      asset_utilization: aggrField('asset_utilization', mergedRow, opRows, fallbackStats.op.asset_utilization),
      maintenance_cost: aggrField('maintenance_cost', mergedRow, opRows, fallbackStats.op.maintenance_cost),
      uptime_percentage: aggrField('uptime_percentage', mergedRow, opRows, fallbackStats.op.uptime_percentage),
      average_inventory: aggrField('average_inventory', mergedRow, opRows, fallbackStats.op.average_inventory),
      beginning_inventory: aggrField('beginning_inventory', mergedRow, opRows, fallbackStats.op.beginning_inventory),
      ending_inventory: aggrField('ending_inventory', mergedRow, opRows, fallbackStats.op.ending_inventory),
      items_received: aggrField('items_received', mergedRow, opRows, fallbackStats.op.items_received),
      items_shipped: aggrField('items_shipped', mergedRow, opRows, fallbackStats.op.items_shipped),
      items_damaged: aggrField('items_damaged', mergedRow, opRows, fallbackStats.op.items_damaged),
      order_volume: aggrField('order_volume', mergedRow, opRows, fallbackStats.op.order_volume),
      employee_count_on_shift: aggrField('employee_count_on_shift', mergedRow, opRows, fallbackStats.op.employee_count_on_shift),
      labor_hours: aggrField('labor_hours', mergedRow, opRows, fallbackStats.op.labor_hours),
      energy_consumption: aggrField('energy_consumption', mergedRow, opRows, fallbackStats.op.energy_consumption),
      maintenance_ticket_count: aggrField('maintenance_ticket_count', mergedRow, opRows, fallbackStats.op.maintenance_ticket_count),
      asset_downtime: aggrField('asset_downtime', mergedRow, opRows, fallbackStats.op.asset_downtime),
      customer_return_count: aggrField('customer_return_count', mergedRow, opRows, fallbackStats.op.customer_return_count),
      backorder_count: aggrField('backorder_count', mergedRow, opRows, fallbackStats.op.backorder_count),
      // PROJECT
      project_id: cleanString(mergedRow.project_id),
      project_name: cleanString(mergedRow.project_name),
      project_manager: cleanString(mergedRow.project_manager),
      start_date: toDate(mergedRow.start_date),
      end_date: toDate(mergedRow.end_date),
      project_status: cleanString(mergedRow.project_status),
      project_budget: aggrField('project_budget', mergedRow, projRows, fallbackStats.project.project_budget),
      actual_project_cost: aggrField('actual_cost', mergedRow, projRows, fallbackStats.project.actual_cost),
      planned_roi: aggrField('planned_roi', mergedRow, projRows, fallbackStats.project.planned_roi),
      actual_roi: aggrField('actual_roi', mergedRow, projRows, fallbackStats.project.actual_roi),
      issue_count: aggrField('issue_count', mergedRow, projRows, fallbackStats.project.issue_count),
      task_completion_rate: aggrField('task_completion_rate', mergedRow, projRows, fallbackStats.project.task_completion_rate),
      stakeholder_satisfaction: aggrField('stakeholder_satisfaction', mergedRow, projRows, fallbackStats.project.stakeholder_satisfaction),
      project_type: cleanString(mergedRow.project_type),
      project_priority: cleanString(mergedRow.project_priority),
      project_phase: cleanString(mergedRow.project_phase),
      methodology: cleanString(mergedRow.methodology),
      planned_end_date: toDate(mergedRow.planned_end_date),
      baseline_end_date: toDate(mergedRow.baseline_end_date),
      committed_cost: aggrField('committed_cost', mergedRow, projRows, fallbackStats.project.committed_cost),
      forecast_cost: aggrField('forecast_cost', mergedRow, projRows, fallbackStats.project.forecast_cost),
      extension_count: aggrField('extension_count', mergedRow, projRows, fallbackStats.project.extension_count),
      change_request_count: aggrField('change_request_count', mergedRow, projRows, fallbackStats.project.change_request_count),
      risk_count: aggrField('risk_count', mergedRow, projRows, fallbackStats.project.risk_count),
      resource_allocated_fte: aggrField('resource_allocated_fte', mergedRow, projRows, fallbackStats.project.resource_allocated_fte),
      resource_utilization_rate: aggrField('resource_utilization_rate', mergedRow, projRows, fallbackStats.project.resource_utilization_rate),
      // STRATEGIC
      strategy_id: cleanString(mergedRow.strategy_id),
      strategy_name: cleanString(mergedRow.strategy_name),
      owner: cleanString(mergedRow.owner),
      owner_position: cleanString(mergedRow.owner_position),
      board_sponsor: cleanString(mergedRow.board_sponsor),
      strategy_status: cleanString(mergedRow.strategy_status),
      planned_end_date_strategy: toDate(mergedRow.planned_end_date),
      strategy_category: cleanString(mergedRow.strategy_category),
      strategy_type: cleanString(mergedRow.strategy_type),
      alignment_with_corporate: cleanString(mergedRow.alignment_with_corporate),
      alignment_with_okr: cleanString(mergedRow.alignment_with_okr),
      strategic_kpi_target: aggrField('strategic_kpi_target', mergedRow, stratRows, fallbackStats.strategic.strategic_kpi_target),
      strategic_kpi_actual: aggrField('strategic_kpi_actual', mergedRow, stratRows, fallbackStats.strategic.strategic_kpi_actual),
      kpi_unit: cleanString(mergedRow.kpi_unit),
      kpi_frequency: cleanString(mergedRow.kpi_frequency),
      risk_level: cleanString(mergedRow.risk_level),
      risk_description: cleanString(mergedRow.risk_description),
      main_risk_owner: cleanString(mergedRow.main_risk_owner),
      mitigation_plan_available: cleanString(mergedRow.mitigation_plan_available),
      initiative_count: aggrField('initiative_count', mergedRow, stratRows, fallbackStats.strategic.initiative_count),
      initiative_success_rate: aggrField('initiative_success_rate', mergedRow, stratRows, fallbackStats.strategic.initiative_success_rate),
      initiative_on_track_count: aggrField('initiative_on_track_count', mergedRow, stratRows, fallbackStats.strategic.initiative_on_track_count),
      initiative_delayed_count: aggrField('initiative_delayed_count', mergedRow, stratRows, fallbackStats.strategic.initiative_delayed_count),
      initiative_completed_count: aggrField('initiative_completed_count', mergedRow, stratRows, fallbackStats.strategic.initiative_completed_count),
      initiative_budget_total: aggrField('initiative_budget_total', mergedRow, stratRows, fallbackStats.strategic.initiative_budget_total),
      initiative_budget_used: aggrField('initiative_budget_used', mergedRow, stratRows, fallbackStats.strategic.initiative_budget_used),
      board_satisfaction: aggrField('board_satisfaction', mergedRow, stratRows, fallbackStats.strategic.board_satisfaction),
      stakeholder_feedback_score: aggrField('stakeholder_feedback_score', mergedRow, stratRows, fallbackStats.strategic.stakeholder_feedback_score),
      last_review_date: toDate(mergedRow.last_review_date),
      resource_allocated_fte_strategy: aggrField('resource_allocated_fte', mergedRow, stratRows, fallbackStats.strategic.resource_allocated_fte),
      resource_utilization_rate_strategy: aggrField('resource_utilization_rate', mergedRow, stratRows, fallbackStats.strategic.resource_utilization_rate),
      expected_benefit_value: aggrField('expected_benefit_value', mergedRow, stratRows, fallbackStats.strategic.expected_benefit_value),
      realized_benefit_value: aggrField('realized_benefit_value', mergedRow, stratRows, fallbackStats.strategic.realized_benefit_value),
      // Tambahan Advanced
      outlier_flags,
      imputed_flags
    };

    const {completeness_score, missing_fields} = computeCompletenessById(obj, obj.id);
    obj.completeness_score = completeness_score;
    obj.embedding = missing_fields;
    obj.confidence_score = confidenceScore(obj, completeness_score, missing_fields);

    output.push(obj);
    itemNumber += 1;
  }
  return output;
}
module.exports = { etlCombinationKPI };
