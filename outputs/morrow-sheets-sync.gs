// Legacy one-way exporter only. Use outputs/Code.gs for the full prototype backend and staff chat.
function doPost(e) {
  try {
    const props = PropertiesService.getScriptProperties();
    const expectedSecret = props.getProperty("SYNC_SECRET") || "";
    const spreadsheetId = props.getProperty("SPREADSHEET_ID") || "";
    const payload = JSON.parse(e && e.postData ? e.postData.contents : "{}");

    if (!expectedSecret || !spreadsheetId || !constantTimeEquals(expectedSecret, payload.secret || "")) {
      return jsonResponse({ ok: false, error: "Unauthorized or not configured" });
    }

    const book = SpreadsheetApp.openById(spreadsheetId);
    const patients = (payload.patients || []).map(row => [
      row.id, row.name, row.phone, row.email, row.dob, row.lastVisit, row.reference, row.createdAt, row.updatedAt
    ]);
    const appointments = (payload.appointments || []).map(row => [
      row.id, row.patientId, row.date, row.time, row.type, row.status, row.reason, row.createdAt, row.updatedAt
    ]);
    const payments = (payload.payments || []).map(row => [
      row.id, row.patientId, row.date, row.amount, row.currency, row.exchangeRate, row.usdAmount, row.method
    ]);

    replaceSheet(book, "Patients", ["Patient ID", "Name", "Phone", "Email", "Date of birth", "Last visit", "Reference", "Created", "Updated"], patients);
    replaceSheet(book, "Appointments", ["Appointment ID", "Patient ID", "Date", "Time", "Type", "Status", "Reason", "Created", "Updated"], appointments);
    replaceSheet(book, "Payments", ["Payment ID", "Patient ID", "Date", "Amount received", "Currency", "LBP per USD", "USD equivalent", "Method"], payments);
    return jsonResponse({ ok: true, syncedAt: new Date().toISOString() });
  } catch (error) {
    return jsonResponse({ ok: false, error: String(error && error.message || error) });
  }
}

function replaceSheet(book, name, headers, rows) {
  const sheet = book.getSheetByName(name) || book.insertSheet(name);
  sheet.clearContents();
  const values = [headers].concat(rows).map(row => row.map(safeCell));
  sheet.getRange(1, 1, values.length, headers.length).setNumberFormat("@");
  sheet.getRange(1, 1, values.length, headers.length).setValues(values);
  sheet.setFrozenRows(1);
}

function safeCell(value) {
  const text = value === null || value === undefined ? "" : String(value);
  return /^[=+\-@]/.test(text) ? "'" + text : text;
}

function constantTimeEquals(a, b) {
  const left = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, a, Utilities.Charset.UTF_8);
  const right = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, b, Utilities.Charset.UTF_8);
  let different = left.length ^ right.length;
  for (let i = 0; i < Math.max(left.length, right.length); i++) different |= (left[i] || 0) ^ (right[i] || 0);
  return different === 0;
}

function jsonResponse(value) {
  return ContentService.createTextOutput(JSON.stringify(value)).setMimeType(ContentService.MimeType.JSON);
}
