const MORROW = {
  dataSheet: "ClinicData",
  usersSheet: "Users",
  messagesSheet: "StaffMessages",
  assetSheet: "Assets",
  dataHeaders: ["Collection", "Record ID", "JSON", "Updated at"],
  userHeaders: ["User ID", "Name", "Email", "Role", "Active", "Permissions JSON", "Salt", "Password hash", "Created at", "Updated at", "Profile image"],
  messageHeaders: ["Message ID", "Sender ID", "Sender name", "Sender role", "Message", "Sent at", "Reactions", "Edited at", "Kind"],
  assetHeaders: ["Asset key", "Part", "Chunk"],
  collections: ["patients", "appointments", "payments", "templates", "activity"],
  permissions: ["dashboard", "appointments", "patients", "clinicalNotes", "calendar", "billing", "communications", "reports"]
};

const DUMMY_SALT = "AAAAAAAAAAAAAAAAAAAAAA==";
const SESSION_SECONDS = 21600;
const LOGIN_LIMIT = 8;
const LOGIN_LOCK_SECONDS = 900;
const ASSET_CHUNK_SIZE = 45000;
const ASSET_MAX_CHARS = 4000000;

function doGet() {
  ensureSchema_();
  return HtmlService.createHtmlOutputFromFile("App").setTitle("Vntera Clinic");
}

function getAuthStatus() {
  ensureSchema_();
  return {
    needsSetup: readUsers_().length === 0,
    setupCodeReady: Boolean(PropertiesService.getScriptProperties().getProperty("FIRST_DOCTOR_SETUP_CODE"))
  };
}

function createFirstDoctorAccount(name, email, credential, setupCode) {
  ensureSchema_();
  const user = withLock_(function () {
    const props = PropertiesService.getScriptProperties();
    const expectedCode = props.getProperty("FIRST_DOCTOR_SETUP_CODE") || "";
    if (!expectedCode || !constantTimeEquals_(expectedCode, String(setupCode || ""))) {
      throw new Error("The one-time setup code did not match");
    }
    if (readUsers_().length) throw new Error("A clinic owner account already exists");
    const clean = validateAccount_(name, email, credential, "Doctor");
    clean.permissions = MORROW.permissions.slice();
    clean.id = Utilities.getUuid();
    clean.active = true;
    clean.createdAt = new Date().toISOString();
    clean.updatedAt = clean.createdAt;
    writeUsers_([clean]);
    props.deleteProperty("FIRST_DOCTOR_SETUP_CODE");
    return clean;
  });
  return newSessionPayload_(user);
}

function getLoginChallenge(email) {
  ensureSchema_();
  const normalized = normalizeEmail_(email);
  const user = readUsers_().find(function (item) { return item.email === normalized; });
  const nonce = Utilities.getUuid().replace(/-/g, "") + Utilities.getUuid().replace(/-/g, "");
  CacheService.getScriptCache().put(loginChallengeKey_(nonce), JSON.stringify({ email: normalized }), 180);
  return { salt: user ? user.salt : DUMMY_SALT, nonce: nonce };
}

function authenticateUser(email, nonce, proof) {
  ensureSchema_();
  const normalized = normalizeEmail_(email);
  const bucket = loginBucket_(normalized);
  const cache = CacheService.getScriptCache();
  const attempts = Number(cache.get(bucket) || 0);
  if (attempts >= LOGIN_LIMIT) return { ok: false, error: "Too many attempts. Try again in 15 minutes." };

  let challenge = null;
  try { challenge = JSON.parse(cache.get(loginChallengeKey_(nonce)) || "null"); } catch (_) { challenge = null; }
  cache.remove(loginChallengeKey_(nonce));
  const user = readUsers_().find(function (item) { return item.email === normalized; });
  const expected = user && challenge && challenge.email === normalized
    ? Utilities.base64Encode(Utilities.computeHmacSha256Signature(String(nonce), Utilities.base64Decode(user.hash)))
    : "";
  const matches = user && user.active && challenge && challenge.email === normalized && constantTimeEquals_(expected, String(proof || ""));
  if (!matches) {
    cache.put(bucket, String(attempts + 1), LOGIN_LOCK_SECONDS);
    return { ok: false, error: "Email or password did not match." };
  }
  cache.remove(bucket);
  return newSessionPayload_(user);
}

function resumeSession(token) {
  ensureSchema_();
  return newSessionPayload_(requireUser_(token));
}

function logoutUser(token) {
  CacheService.getScriptCache().remove(sessionKey_(token));
  return { ok: true };
}

function updateMyProfile(token, input) {
  ensureSchema_();
  const actor = requireUser_(token);
  input = input && typeof input === "object" ? input : {};
  return withLock_(function () {
    const users = readUsers_();
    const user = users.find(function (item) { return item.id === actor.id; });
    if (!user) throw new Error("Your account no longer exists");

    let name = user.name;
    if (input.name !== undefined) {
      name = cleanText_(input.name, 80).trim();
      if (!name) throw new Error("Enter your name");
    }
    let email = user.email;
    if (input.email !== undefined) {
      email = normalizeEmail_(input.email);
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new Error("Enter a valid login email");
      if (users.some(function (item) { return item.id !== user.id && item.email === email; })) {
        throw new Error("An account already uses that email");
      }
    }

    const credential = input.credential;
    if (credential && credential.salt && credential.hash) {
      const proof = input.currentProof;
      if (!proof || !proof.nonce || !proof.proof) throw new Error("Enter your current password to set a new one");
      const cache = CacheService.getScriptCache();
      const nonce = String(proof.nonce);
      let challenge = null;
      try { challenge = JSON.parse(cache.get(loginChallengeKey_(nonce)) || "null"); } catch (_) { challenge = null; }
      cache.remove(loginChallengeKey_(nonce));
      const expected = challenge && challenge.email === user.email
        ? Utilities.base64Encode(Utilities.computeHmacSha256Signature(nonce, Utilities.base64Decode(user.hash)))
        : "";
      if (!constantTimeEquals_(expected, String(proof.proof || ""))) throw new Error("Your current password did not match");
      const salt = String(credential.salt);
      const hash = String(credential.hash);
      if (!/^[A-Za-z0-9+/]{22}==$/.test(salt) || !/^[A-Za-z0-9+/]{43}=$/.test(hash)) {
        throw new Error("The password could not be safely prepared. Try again in a current browser.");
      }
      user.salt = salt;
      user.hash = hash;
    }

    if (input.image !== undefined) {
      const raw = String(input.image || "");
      if (raw && !/^data:image\/(?:png|jpe?g|webp|gif);base64,/i.test(raw)) throw new Error("The profile photo is invalid");
      if (raw.length > 46000) throw new Error("That profile photo is too large. Choose a smaller image");
      user.image = raw;
    }

    user.name = name;
    user.email = email;
    user.updatedAt = new Date().toISOString();
    writeUsers_(users);
    return { ok: true, user: publicUser_(user, true), users: publicUsers_(users, true) };
  });
}

function loadDatabase(token) {
  ensureSchema_();
  const user = requireUser_(token);
  const stored = withLock_(function () { return readClinicData_(); });
  return { database: filterDatabaseForUser_(stored.database, user), revision: stored.revision };
}

function syncSession(token, knownRevision) {
  ensureSchema_();
  return withLock_(function () {
    const user = requireUser_(token);
    const revision = readClinicRevision_();
    const changed = Number(knownRevision) !== revision;
    const database = changed ? filterDatabaseForUser_(readClinicData_().database, user) : null;
    return {
      user: publicUser_(user, true),
      users: publicUsers_(readUsers_(), user.role === "Doctor"),
      revision: revision,
      database: database
    };
  });
}

function saveDatabase(token, incoming, expectedRevision) {
  ensureSchema_();
  const user = requireUser_(token);
  return withLock_(function () {
    const current = readClinicData_();
    const expected = Number(expectedRevision);
    if (!Number.isFinite(expected) || expected !== current.revision) {
      return { ok: false, conflict: true, revision: current.revision };
    }
    const next = applyPermittedChanges_(current.database, incoming, user);
    const revision = current.revision + 1;
    writeClinicData_(next, revision);
    return { ok: true, revision: revision };
  });
}

function saveStaffUser(token, input) {
  ensureSchema_();
  const actor = requireUser_(token);
  requireDoctor_(actor);
  return withLock_(function () {
    const users = readUsers_();
    const id = String(input && input.id || "");
    let user = users.find(function (item) { return item.id === id; });
    if (id && !user) throw new Error("That staff account no longer exists");
    if (user && user.role === "Doctor") throw new Error("The owner account cannot be edited here");
    const email = normalizeEmail_(input && input.email);
    if (users.some(function (item) { return item.email === email && item.id !== id; })) {
      throw new Error("A staff account already uses that email");
    }
    const clean = validateAccount_(input && input.name, email, input && input.credential, "Receptionist", Boolean(user));
    if (!user) {
      user = { id: Utilities.getUuid(), role: "Receptionist", active: true, createdAt: new Date().toISOString() };
      users.push(user);
    }
    user.name = clean.name;
    user.email = clean.email;
    user.permissions = normalizePermissions_(input && input.permissions);
    if (clean.salt && clean.hash) {
      user.salt = clean.salt;
      user.hash = clean.hash;
    }
    user.updatedAt = new Date().toISOString();
    writeUsers_(users);
    return { ok: true, users: publicUsers_(users, true) };
  });
}

function setStaffActive(token, id, active) {
  ensureSchema_();
  const actor = requireUser_(token);
  requireDoctor_(actor);
  return withLock_(function () {
    const users = readUsers_();
    const user = users.find(function (item) { return item.id === String(id); });
    if (!user || user.role === "Doctor") throw new Error("That staff account cannot be changed");
    user.active = Boolean(active);
    user.updatedAt = new Date().toISOString();
    writeUsers_(users);
    return { ok: true, users: publicUsers_(users, true) };
  });
}

function deleteStaffUser(token, id) {
  ensureSchema_();
  const actor = requireUser_(token);
  requireDoctor_(actor);
  return withLock_(function () {
    const users = readUsers_();
    const user = users.find(function (item) { return item.id === String(id); });
    if (!user || user.role === "Doctor") throw new Error("The owner account cannot be deleted");
    writeUsers_(users.filter(function (item) { return item.id !== user.id; }));
    return { ok: true, users: publicUsers_(readUsers_(), true) };
  });
}

function listStaffMessages(token) {
  ensureSchema_();
  const user = requireUser_(token);
  requirePermission_(user, "communications");
  return withLock_(function () {
    const messages = readMessages_();
    const now = Date.now();
    const expired = messages.filter(function (message) {
      const ttl = String(message.kind || "") === "schedule" ? 7 * 24 * 60 * 60 * 1000 : 36 * 60 * 60 * 1000;
      return new Date(message.createdAt).getTime() < now - ttl;
    });
    if (expired.length) {
      const expiredIds = expired.map(function (message) { return String(message.id); });
      const sheet = getSheet_(MORROW.messagesSheet, MORROW.messageHeaders);
      for (let index = expiredIds.length - 1; index >= 0; index--) {
        const row = findMessageRow_(sheet, expiredIds[index]);
        if (row > 0) sheet.deleteRow(row + 1);
      }
      return readMessages_();
    }
    return messages;
  });
}

function findMessageRow_(sheet, id) {
  const values = sheet.getDataRange().getValues();
  for (let index = 1; index < values.length; index++) {
    if (String(values[index][0]) === String(id)) return index;
  }
  return -1;
}

function editStaffMessage(token, input) {
  ensureSchema_();
  const user = requireUser_(token);
  requirePermission_(user, "communications");
  const messageId = String((input && input.messageId) || "");
  const body = cleanText_(input && input.body, 1500).trim();
  if (!messageId) throw new Error("That message no longer exists");
  if (!body) throw new Error("Write a message before saving");
  return withLock_(function () {
    const sheet = getSheet_(MORROW.messagesSheet, MORROW.messageHeaders);
    const rowIndex = findMessageRow_(sheet, messageId);
    if (rowIndex < 0) throw new Error("That message no longer exists");
    if (user.role !== "Doctor" && String(sheet.getRange(rowIndex + 1, 2).getValue()) !== user.id) throw new Error("You can only edit your own messages");
    sheet.getRange(rowIndex + 1, 5).setValue(body);
    sheet.getRange(rowIndex + 1, 8).setValue(new Date().toISOString());
    const values = sheet.getRange(rowIndex + 1, 1, 1, MORROW.messageHeaders.length).getValues()[0];
    return { id: String(values[0]), senderId: String(values[1]), senderName: String(values[2]), senderRole: String(values[3]), body: String(values[4]), createdAt: String(values[5]), reactions: parseReactionsCell_(values[6]), editedAt: String(values[7] || ""), kind: String(values[8] || "") };
  });
}

function deleteStaffMessages(token, ids) {
  ensureSchema_();
  const user = requireUser_(token);
  requirePermission_(user, "communications");
  const list = (Array.isArray(ids) ? ids : []).map(String).filter(Boolean);
  if (!list.length) return { ok: true, deleted: 0 };
  return withLock_(function () {
    const sheet = getSheet_(MORROW.messagesSheet, MORROW.messageHeaders);
    const values = sheet.getDataRange().getValues();
    const doctor = user.role === "Doctor";
    const rows = [];
    for (let index = 1; index < values.length; index++) {
      const id = String(values[index][0]);
      if (list.indexOf(id) < 0) continue;
      if (!doctor && String(values[index][1]) !== user.id) throw new Error("You can only delete your own messages");
      rows.push(index + 1);
    }
    if (!rows.length) throw new Error("Those messages no longer exist");
    rows.sort(function (a, b) { return b - a; }).forEach(function (row) { sheet.deleteRow(row); });
    return { ok: true, deleted: rows.length };
  });
}

function sendStaffMessage(token, input) {
  ensureSchema_();
  const user = requireUser_(token);
  requirePermission_(user, "communications");
  return withLock_(function () {
    const body = cleanText_(input && input.body, 1500).trim();
    if (!body) throw new Error("Write a message before sending");
    const kind = input && input.kind === "schedule" ? "schedule" : "";
    const message = {
      id: Utilities.getUuid(),
      senderId: user.id,
      senderName: user.name,
      senderRole: user.role,
      body: body,
      createdAt: new Date().toISOString(),
      kind: kind
    };
    const sheet = getSheet_(MORROW.messagesSheet, MORROW.messageHeaders);
    if (kind === "schedule") {
      const staleIds = readMessages_().filter(function (item) { return String(item.kind || "") === "schedule"; }).map(function (item) { return item.id; });
      for (let index = staleIds.length - 1; index >= 0; index--) {
        const staleRow = findMessageRow_(sheet, staleIds[index]);
        if (staleRow > 0) sheet.deleteRow(staleRow + 1);
      }
    }
    const row = [message.id, message.senderId, message.senderName, message.senderRole, message.body, message.createdAt, "", "", kind].map(safeCell_);
    sheet.getRange(Math.max(2, sheet.getLastRow() + 1), 1, 1, row.length).setNumberFormat("@").setValues([row]);
    return message;
  });
}

function deleteStaffMessage(token, id) {
  ensureSchema_();
  const user = requireUser_(token);
  requirePermission_(user, "communications");
  return withLock_(function () {
    const sheet = getSheet_(MORROW.messagesSheet, MORROW.messageHeaders);
    const values = sheet.getDataRange().getValues();
    for (let index = 1; index < values.length; index++) {
      if (String(values[index][0]) !== String(id)) continue;
      if (user.role !== "Doctor" && String(values[index][1]) !== user.id) throw new Error("You can only delete your own messages");
      sheet.deleteRow(index + 1);
      return { ok: true };
    }
    throw new Error("That message no longer exists");
  });
}

const CHAT_REACTIONS_ = ["\u{1F44D}", "\u{2764}\u{FE0F}", "\u{1F602}", "\u{1F62E}", "\u{1F622}", "\u{1F64F}"];

function parseReactionsCell_(value) {
  if (!value) return {};
  try {
    const parsed = JSON.parse(String(value));
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch (_) { return {}; }
}

function reactStaffMessage(token, input) {
  ensureSchema_();
  const user = requireUser_(token);
  requirePermission_(user, "communications");
  const messageId = String((input && input.messageId) || "");
  const emoji = String((input && input.emoji) || "");
  if (!messageId) throw new Error("That message no longer exists");
  if (emoji && CHAT_REACTIONS_.indexOf(emoji) < 0) throw new Error("Choose a different reaction");
  return withLock_(function () {
    const sheet = getSheet_(MORROW.messagesSheet, MORROW.messageHeaders);
    const values = sheet.getDataRange().getValues();
    for (let index = 1; index < values.length; index++) {
      if (String(values[index][0]) !== messageId) continue;
      const reactions = parseReactionsCell_(values[index][6]);
      if (emoji) reactions[user.id] = emoji;
      else delete reactions[user.id];
      sheet.getRange(index + 1, 7).setNumberFormat("@").setValues([[safeCell_(JSON.stringify(reactions))]]);
      return {
        id: messageId,
        senderId: String(values[index][1]),
        senderName: String(values[index][2]),
        senderRole: String(values[index][3]),
        body: String(values[index][4]),
        createdAt: String(values[index][5]),
        reactions: reactions
      };
    }
    throw new Error("That message no longer exists");
  });
}

function newSessionPayload_(user) {
  const token = issueSession_(user);
  const stored = withLock_(function () { return readClinicData_(); });
  return {
    ok: true,
    token: token,
    user: publicUser_(user, true),
    database: filterDatabaseForUser_(stored.database, user),
    revision: stored.revision
  };
}

function issueSession_(user) {
  const token = Utilities.getUuid().replace(/-/g, "") + Utilities.getUuid().replace(/-/g, "");
  CacheService.getScriptCache().put(sessionKey_(token), user.id, SESSION_SECONDS);
  return token;
}

function requireUser_(token) {
  const id = CacheService.getScriptCache().get(sessionKey_(token));
  if (!id) throw new Error("Your clinic session expired. Sign in again.");
  const user = readUsers_().find(function (item) { return item.id === id && item.active; });
  if (!user) throw new Error("This staff account is inactive. Contact the clinic doctor.");
  return user;
}

function sessionKey_(token) {
  return "morrow-session:" + cleanText_(token, 100);
}

function applyPermittedChanges_(current, incoming, user) {
  if (!incoming || typeof incoming !== "object" || Array.isArray(incoming)) throw new Error("The clinic data is invalid");
  const next = clone_(current);
  const records = {};
  MORROW.collections.forEach(function (name) { records[name] = cleanRecords_(incoming[name], name); });

  if (user.role === "Doctor") {
    MORROW.collections.forEach(function (name) { if (name !== "activity") next[name] = records[name]; });
    next.settings = cleanSettings_(incoming.settings);
    next.theme = ["forest", "ocean", "violet", "terracotta", "night", "blush", "teal", "amber", "indigo", "crimson"].indexOf(incoming.theme) >= 0 ? incoming.theme : "ocean";
    next.animations = Boolean(incoming.animations);
    next.sections = incoming.sections && typeof incoming.sections === "object" ? incoming.sections : next.sections;
  } else {
    if (hasPermission_(user, "patients")) {
      const previous = new Map((current.patients || []).map(function (item) { return [item.id, item]; }));
      next.patients = records.patients.map(function (item) {
        if (!hasPermission_(user, "clinicalNotes")) {
          const prior = previous.get(item.id);
          item.notes = prior ? String(prior.notes || "") : "";
        }
        return item;
      });
    }
    if (hasPermission_(user, "appointments")) next.appointments = records.appointments;
    if (hasPermission_(user, "billing")) next.payments = records.payments;
    if (hasPermission_(user, "communications")) {
      next.templates = records.templates;
    }
  }
  next.activity = mergeActivity_(current.activity, records.activity);
  next.version = 2;
  next.lastSaved = new Date().toISOString();
  next.users = undefined;
  next.staffMessages = undefined;
  return next;
}

function mergeActivity_(currentList, incomingList) {
  const merged = {};
  (Array.isArray(currentList) ? currentList : []).forEach(function (entry) {
    if (entry && entry.id) merged[entry.id] = entry;
  });
  (Array.isArray(incomingList) ? incomingList : []).forEach(function (entry) {
    if (entry && entry.id && !merged[entry.id]) merged[entry.id] = entry;
  });
  return Object.keys(merged)
    .map(function (id) { return merged[id]; })
    .sort(function (a, b) { return String(b.createdAt || "").localeCompare(String(a.createdAt || "")); })
    .slice(0, 500);
}

function filterDatabaseForUser_(database, user) {
  const result = clone_(database);
  result.users = publicUsers_(readUsers_(), user.role === "Doctor");
  result.staffMessages = [];
  result.settings = cleanSettings_(result.settings);

  const canPatients = user.role === "Doctor" || hasPermission_(user, "patients");
  const canAppointments = user.role === "Doctor" || hasPermission_(user, "appointments");
  const canCalendar = user.role === "Doctor" || hasPermission_(user, "calendar");
  const canBilling = user.role === "Doctor" || hasPermission_(user, "billing");
  const canReports = user.role === "Doctor" || hasPermission_(user, "reports");
  const canNotes = user.role === "Doctor" || hasPermission_(user, "clinicalNotes");

  if (!canPatients) {
    if (canAppointments || canCalendar || canBilling || canReports) {
      result.patients = (result.patients || []).map(function (person) {
        return { id: person.id, name: person.name, reference: person.reference || "", lastVisit: person.lastVisit || "", visitCount: person.visitCount || 0 };
      });
    } else result.patients = [];
  } else if (!canNotes) {
    result.patients = (result.patients || []).map(function (person) {
      const copy = clone_(person);
      delete copy.notes;
      return copy;
    });
  }

  if (!canAppointments && !canCalendar && !canReports) result.appointments = [];
  else if (!canAppointments) result.appointments = (result.appointments || []).map(function (item) {
    return { id: item.id, patientId: item.patientId, date: item.date, time: item.time, type: item.type, status: item.status, createdAt: item.createdAt, updatedAt: item.updatedAt };
  });

  if (!canBilling && !canReports) result.payments = [];
  else if (!canBilling) result.payments = (result.payments || []).map(function (item) {
    return { id: item.id, date: item.date, amount: item.amount, currency: item.currency, exchangeRate: item.exchangeRate, usdAmount: item.usdAmount, method: item.method };
  });

  if (user.role !== "Doctor" && !hasPermission_(user, "communications")) {
    result.templates = [];
    result.activity = [];
  }
  return result;
}

function readClinicData_() {
  const sheet = getSheet_(MORROW.dataSheet, MORROW.dataHeaders);
  const values = sheet.getDataRange().getValues();
  const database = defaultDatabase_();
  let revision = 0;
  let hasState = false;
  for (let index = 1; index < values.length; index++) {
    const collection = String(values[index][0] || "");
    const id = String(values[index][1] || "");
    const json = values[index][2];
    if (!json) continue;
    let record;
    try { record = JSON.parse(String(json)); } catch (_) { continue; }
    if (collection === "meta" && id === "state") {
      revision = Number(record.revision) || 0;
      Object.assign(database, record.state || {});
      hasState = true;
    } else if (MORROW.collections.indexOf(collection) >= 0) {
      database[collection].push(record);
    }
  }
  if (!hasState) database.templates = defaultTemplates_();
  database.users = [];
  database.staffMessages = [];
  database.settings = cleanSettings_(database.settings);
  return { database: database, revision: revision };
}

function readClinicRevision_() {
  const sheet = getSheet_(MORROW.dataSheet, MORROW.dataHeaders);
  if (sheet.getLastRow() < 2) return 0;
  const row = sheet.getRange(2, 1, 1, 3).getValues()[0];
  if (String(row[0]) !== "meta" || String(row[1]) !== "state") return 0;
  try {
    const meta = JSON.parse(String(row[2] || "{}"));
    return Number(meta.revision) || 0;
  } catch (_) {
    return 0;
  }
}

function writeClinicData_(input, revision) {
  const database = clone_(input);
  const state = clone_(database);
  MORROW.collections.forEach(function (name) { delete state[name]; });
  delete state.users;
  delete state.staffMessages;
  state.settings = cleanSettings_(state.settings);
  const now = new Date().toISOString();
  state.lastSaved = now;
  const rows = [["meta", "state", JSON.stringify({ revision: revision, state: state }), now]];
  MORROW.collections.forEach(function (name) {
    const records = Array.isArray(database[name]) ? database[name] : [];
    records.forEach(function (record) {
      rows.push([name, String(record.id), JSON.stringify(record), String(record.updatedAt || now)]);
    });
  });
  const sheet = getSheet_(MORROW.dataSheet, MORROW.dataHeaders);
  sheet.clearContents();
  sheet.getRange(1, 1, 1, MORROW.dataHeaders.length).setValues([MORROW.dataHeaders]);
  const safeRows = rows.map(function (row) { return row.map(safeCell_); });
  sheet.getRange(2, 1, safeRows.length, MORROW.dataHeaders.length).setNumberFormat("@").setValues(safeRows);
  sheet.setFrozenRows(1);
}

function defaultDatabase_() {
  return {
    version: 2,
    patients: [],
    appointments: [],
    payments: [],
    templates: [],
    activity: [],
    settings: { clinicName: "My Clinic", clinicPhone: "", timezone: "UTC", lbpPerUsd: "", emailMode: "mailto", emailFrom: "", emailEndpoint: "", welcomeImage: "" },
    theme: "ocean",
    animations: true,
    sections: { banner: true, statAppointments: true, statPatients: true, statPending: true, statCollected: true, minical: true, today: true, week: true, collections: true, followups: true, availability: true },
    lastSaved: null
  };
}

function defaultTemplates_() {
  return [
    { id: "tpl-confirm", name: "Appointment confirmation", subject: "Your appointment at {clinic_name}", body: "Hello {patient_name},\n\nYour appointment is booked for {appointment_date} at {appointment_time}.\n\nPlease contact our office if you need to make a change.\n\n{clinic_name}" },
    { id: "tpl-reminder", name: "Appointment reminder", subject: "Reminder: visit on {appointment_date}", body: "Hello {patient_name},\n\nThis is a reminder about your appointment on {appointment_date} at {appointment_time}.\n\nWe look forward to seeing you.\n\n{clinic_name}" },
    { id: "tpl-receipt", name: "Payment receipt", subject: "Receipt from {clinic_name}", body: "Hello {patient_name},\n\nWe received your payment of {amount_usd} USD.\n\nThank you,\n{clinic_name}" }
  ];
}

function cleanRecords_(input, name) {
  if (!Array.isArray(input)) throw new Error("The " + name + " records are invalid");
  if (input.length > 5000) throw new Error("The " + name + " list is too large");
  const ids = new Set();
  return input.map(function (item) {
    if (!item || typeof item !== "object" || Array.isArray(item)) throw new Error("A " + name + " record is invalid");
    const copy = clone_(item);
    const id = cleanText_(copy.id, 100);
    if (!id || ids.has(id)) throw new Error("The " + name + " list contains a missing or repeated ID");
    if (JSON.stringify(copy).length > 45000) throw new Error("A " + name + " record is too large for Sheets");
    ids.add(id);
    copy.id = id;
    if (name === "patients") copy.notes = cleanText_(copy.notes, 4000);
    return copy;
  });
}

function cleanSettings_(input) {
  const value = input && typeof input === "object" ? clone_(input) : {};
  delete value.sheetsUrl;
  delete value.sheetsSecret;
  delete value.sheetsConsent;
  delete value.sheetsReady;
  delete value.sheetsRevision;
  return value;
}

function readUsers_() {
  const sheet = getSheet_(MORROW.usersSheet, MORROW.userHeaders);
  const values = sheet.getDataRange().getValues();
  return values.slice(1).filter(function (row) { return row[0] && row[2]; }).map(function (row) {
    let permissions = [];
    try { permissions = JSON.parse(String(row[5] || "[]")); } catch (_) { permissions = []; }
    return {
      id: String(row[0]), name: String(row[1]), email: normalizeEmail_(row[2]),
      role: String(row[3]), active: row[4] === true || String(row[4]).toLowerCase() === "true",
      permissions: normalizePermissions_(permissions), salt: String(row[6]), hash: String(row[7]),
      createdAt: String(row[8] || ""), updatedAt: String(row[9] || ""), image: row[10] ? String(row[10]) : ""
    };
  });
}

function writeUsers_(users) {
  const sheet = getSheet_(MORROW.usersSheet, MORROW.userHeaders);
  sheet.clearContents();
  sheet.getRange(1, 1, 1, MORROW.userHeaders.length).setValues([MORROW.userHeaders]);
  if (users.length) {
    const rows = users.map(function (user) {
      return [user.id, user.name, user.email, user.role, Boolean(user.active), JSON.stringify(user.permissions || []), user.salt, user.hash, user.createdAt, user.updatedAt, user.image || ""].map(safeCell_);
    });
    sheet.getRange(2, 1, rows.length, MORROW.userHeaders.length).setNumberFormat("@").setValues(rows);
  }
  sheet.setFrozenRows(1);
}

function publicUsers_(users, includePrivateFields) {
  return users.map(function (user) {
    const result = { id: user.id, name: user.name, role: user.role, active: Boolean(user.active), permissions: user.permissions || [], image: user.image || "" };
    if (includePrivateFields) result.email = user.email;
    return result;
  });
}

function publicUser_(user, includePermissions) {
  return {
    id: user.id, name: user.name, email: user.email, role: user.role,
    active: Boolean(user.active), permissions: includePermissions ? user.permissions || [] : [],
    image: user.image || ""
  };
}

function validateAccount_(name, email, credential, role, allowPasswordBlank) {
  const cleanName = cleanText_(name, 80).trim();
  const cleanEmail = normalizeEmail_(email);
  if (!cleanName) throw new Error("Enter the staff member's name");
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) throw new Error("Enter a valid login email");
  let salt = "", hash = "";
  if (credential && credential.salt && credential.hash) {
    salt = String(credential.salt);
    hash = String(credential.hash);
    if (!/^[A-Za-z0-9+/]{22}==$/.test(salt) || !/^[A-Za-z0-9+/]{43}=$/.test(hash)) {
      throw new Error("The password could not be safely prepared. Try again in a current browser.");
    }
  } else if (!allowPasswordBlank) {
    throw new Error("Set a password with at least 10 characters");
  }
  return { name: cleanName, email: cleanEmail, role: role, salt: salt, hash: hash };
}

function normalizePermissions_(input) {
  const values = Array.isArray(input) ? input.map(String) : [];
  return Array.from(new Set(values.filter(function (item) { return MORROW.permissions.indexOf(item) >= 0; })));
}

function hasPermission_(user, permission) {
  return user.role === "Doctor" || (user.permissions || []).indexOf(permission) >= 0;
}

function requirePermission_(user, permission) {
  if (!hasPermission_(user, permission)) throw new Error("Your account does not have access to this feature");
}

function requireDoctor_(user) {
  if (user.role !== "Doctor") throw new Error("Only the clinic doctor can manage staff accounts");
}

function normalizeEmail_(email) {
  return cleanText_(email, 140).trim().toLowerCase();
}

function loginBucket_(email) {
  const digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, email || "unknown", Utilities.Charset.UTF_8);
  return "morrow-login:" + digest.map(function (byte) { return ((byte + 256) % 256).toString(16).padStart(2, "0"); }).join("");
}

function loginChallengeKey_(nonce) {
  return "morrow-login-challenge:" + cleanText_(nonce, 100);
}

function readMessages_() {
  const sheet = getSheet_(MORROW.messagesSheet, MORROW.messageHeaders);
  const values = sheet.getDataRange().getValues();
  return values.slice(1).filter(function (row) { return row[0] && row[4]; }).slice(-300).map(function (row) {
    return { id: String(row[0]), senderId: String(row[1]), senderName: String(row[2]), senderRole: String(row[3]), body: String(row[4]), createdAt: String(row[5]), reactions: parseReactionsCell_(row[6]), editedAt: String(row[7] || ""), kind: String(row[8] || "") };
  });
}

function ensureSchema_() {
  withLock_(function () {
    getSheet_(MORROW.dataSheet, MORROW.dataHeaders);
    const userSheet = getSheet_(MORROW.usersSheet, MORROW.userHeaders);
    getSheet_(MORROW.messagesSheet, MORROW.messageHeaders);
    getSheet_(MORROW.assetSheet, MORROW.assetHeaders);
    if (userSheet.getLastRow() <= 1) migrateLegacyUsers_();
  });
}

function migrateLegacyUsers_() {
  const sheet = getSheet_(MORROW.dataSheet, MORROW.dataHeaders);
  const values = sheet.getDataRange().getValues();
  const users = [];
  for (let index = 1; index < values.length; index++) {
    if (String(values[index][0]) !== "users" || !values[index][2]) continue;
    try {
      const user = JSON.parse(String(values[index][2]));
      if (user.id && user.email && user.salt && user.hash) {
        users.push({ id: String(user.id), name: cleanText_(user.name, 80), email: normalizeEmail_(user.email), role: user.role === "Doctor" ? "Doctor" : "Receptionist", active: user.active !== false, permissions: normalizePermissions_(user.permissions), salt: String(user.salt), hash: String(user.hash), createdAt: String(user.createdAt || ""), updatedAt: String(user.updatedAt || "") });
      }
    } catch (_) { }
  }
  if (users.length) writeUsers_(users);
}

function getSpreadsheet_() {
  const id = PropertiesService.getScriptProperties().getProperty("SPREADSHEET_ID");
  if (!id) throw new Error("Set the SPREADSHEET_ID Script Property in Apps Script");
  return SpreadsheetApp.openById(id);
}

function getSheet_(name, headers) {
  const book = getSpreadsheet_();
  let sheet = book.getSheetByName(name);
  if (!sheet) sheet = book.insertSheet(name);
  if (sheet.getLastRow() === 0) {
    sheet.getRange(1, 1, 1, headers.length).setValues([headers]);
    sheet.setFrozenRows(1);
  } else {
    const current = sheet.getRange(1, 1, 1, headers.length).getValues()[0];
    let changed = false;
    for (let index = 0; index < headers.length; index++) {
      if (String(current[index] == null ? "" : current[index]) !== headers[index]) { current[index] = headers[index]; changed = true; }
    }
    if (changed) sheet.getRange(1, 1, 1, headers.length).setValues([current]);
  }
  return sheet;
}

function withLock_(callback) {
  const lock = LockService.getScriptLock();
  lock.waitLock(20000);
  try { return callback(); } finally { lock.releaseLock(); }
}

function constantTimeEquals_(leftValue, rightValue) {
  const left = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, String(leftValue || ""), Utilities.Charset.UTF_8);
  const right = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, String(rightValue || ""), Utilities.Charset.UTF_8);
  let difference = left.length ^ right.length;
  for (let index = 0; index < Math.max(left.length, right.length); index++) difference |= (left[index] || 0) ^ (right[index] || 0);
  return difference === 0;
}

function clone_(value) {
  return JSON.parse(JSON.stringify(value));
}

function cleanText_(value, maxLength) {
  return String(value == null ? "" : value).replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, "").slice(0, maxLength);
}

function safeCell_(value) {
  const text = String(value == null ? "" : value);
  return /^[=+\-@]/.test(text) ? "'" + text : text;
}

// ---- Welcome banner image asset (chunked into the Assets sheet; keeps multi-MB images out of the settings cell) ----

function uploadWelcomeAsset(token, dataUrl) {
  ensureSchema_();
  const actor = requireUser_(token);
  requireDoctor_(actor);
  const text = String(dataUrl || "");
  if (!/^data:image\/(png|jpeg|jpg|webp|gif);base64,/.test(text)) {
    throw new Error("The welcome image must be an uploaded image file");
  }
  if (text.length > ASSET_MAX_CHARS) {
    throw new Error("The welcome image is too large. Upload an image up to 5 MB.");
  }
  if (text.length < 100) throw new Error("The welcome image data is invalid");
  return withLock_(function () {
    writeAsset_("welcomeBanner", text);
    return { ok: true, chars: text.length };
  });
}

function getWelcomeAsset(token) {
  ensureSchema_();
  requireUser_(token);
  return withLock_(function () { return readAsset_("welcomeBanner"); });
}

function deleteWelcomeAsset(token) {
  ensureSchema_();
  const actor = requireUser_(token);
  requireDoctor_(actor);
  return withLock_(function () { deleteAsset_("welcomeBanner"); return { ok: true }; });
}

function writeAsset_(key, text) {
  deleteAsset_(key);
  const sheet = getSheet_(MORROW.assetSheet, MORROW.assetHeaders);
  const rows = [];
  for (let offset = 0; offset < text.length; offset += ASSET_CHUNK_SIZE) {
    rows.push([key, rows.length, text.slice(offset, offset + ASSET_CHUNK_SIZE)]);
  }
  if (rows.length) {
    sheet.getRange(sheet.getLastRow() + 1, 1, rows.length, 3).setValues(rows);
  }
}

function readAsset_(key) {
  const sheet = getSheet_(MORROW.assetSheet, MORROW.assetHeaders);
  const lastRow = sheet.getLastRow();
  if (lastRow < 2) return "";
  const values = sheet.getRange(2, 1, lastRow - 1, 3).getValues();
  const parts = [];
  for (let index = 0; index < values.length; index++) {
    if (String(values[index][0]) === key) parts.push([Number(values[index][1]) || 0, String(values[index][2] || "")]);
  }
  parts.sort(function (a, b) { return a[0] - b[0]; });
  return parts.map(function (part) { return part[1]; }).join("");
}

function deleteAsset_(key) {
  const sheet = getSheet_(MORROW.assetSheet, MORROW.assetHeaders);
  const lastRow = sheet.getLastRow();
  if (lastRow < 2) return;
  const values = sheet.getRange(2, 1, lastRow - 1, 3).getValues();
  for (let index = values.length - 1; index >= 0; index--) {
    if (String(values[index][0]) === key) sheet.deleteRow(index + 2);
  }
}
