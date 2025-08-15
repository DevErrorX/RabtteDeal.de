const admin = require("firebase-admin");

// Initialize Firebase only once
if (!admin.apps.length) {
  const serviceAccount = require("./path/to/serviceAccountKey.json");

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: "https://rabattedealde-23a0d-default-rtdb.firebaseio.com"
  });
}

const db = admin.database();
const dealsRef = db.ref("deals");

module.exports = { db, dealsRef };
