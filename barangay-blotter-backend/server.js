const express = require("express");
// FIX: Use the promise-based version of mysql2 for async/await
const mysql = require("mysql2/promise"); 
const cors = require("cors");
const bcrypt = require("bcrypt");
const path = require("path");

const app = express();
app.use(cors());
app.use(express.json());

// Serve frontend files from parent directory
app.use(express.static(path.join(__dirname, "..")));

// ✅ MySQL connection - Using createPool for better resource management
const db = mysql.createPool({ // Changed to createPool
  host: "localhost",
  user: "root",
  password: "", // XAMPP default
  database: "barangay_blotter",
  // FIX: timezone is handled by the connection, not the pool object itself.
  // We rely on the date formatting in the queries for PH time.
});

// ✅ Test Connection to MySQL
db.getConnection()
  .then(connection => {
    console.log("✅ Connected to MySQL Database (using Pool)!");
    connection.release(); // Release the connection back to the pool
  })
  .catch(err => {
    console.error("Database connection failed:", err);
  });

// ---------- REGISTER (FIXED to use async/await) ----------
app.post("/register", async (req, res) => {
  const { user_type, name, email, address, contact, password } = req.body;

  if (!user_type || !name || !email || !address || !contact || !password) {
    return res.status(400).json({ message: "Please fill all fields." });
  }

  try {
    const checkEmailSql = "SELECT * FROM users WHERE email = ?";
    const [results] = await db.query(checkEmailSql, [email]);

    if (results.length > 0) {
      return res.status(400).json({ message: "Email already exists!" });
    }

    const saltRounds = 10;
    const hash = await bcrypt.hash(password, saltRounds);

    const sql = "INSERT INTO users (user_type, name, email, address, contact, password) VALUES (?, ?, ?, ?, ?, ?)";
    const [result] = await db.query(sql, [user_type, name, email, address, contact, hash]);

    console.log("Insert success:", result);
    res.json({ message: "User registered successfully!" });
  } catch (err) {
    console.error("Database/Server Error:", err);
    res.status(500).json({ message: "Server error during registration." });
  }
});

// ---------- LOGIN (FIXED to use async/await) ----------
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Please fill all fields." });
  }

  try {
    const sql = "SELECT * FROM users WHERE email = ?";
    const [results] = await db.query(sql, [email]);

    if (results.length === 0) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    const user = results[0];

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    res.json({
      message: "Login successful!",
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        contact: user.contact,
        address: user.address,
        user_type: user.user_type
      }
    });
  } catch (err) {
    console.error("Database/Bcrypt Error:", err);
    res.status(500).json({ message: "Server error during login." });
  }
});

// ---------- ADD COMPLAINT (FIXED to use async/await) ----------
app.post("/add-complaint", async (req, res) => {
  console.log("📥 Received complaint data:", req.body);
  const { user_id, user_name, contact, date, time, personToReport, incidentType, details } = req.body;

  if (!user_id || !user_name || !contact || !date || !time || !personToReport || !incidentType || !details) {
    return res.status(400).json({ message: "Please fill out all required fields." });
  }

  try {
    const sql = `
      INSERT INTO complaints (user_id, user_name, contact, date, time, personToReport, incident_type, details)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `;
    const [result] = await db.query(sql, [user_id, user_name, contact, date, time, personToReport, incidentType, details]);

    console.log("✅ Complaint successfully recorded:", result);
    res.json({ message: "Complaint successfully recorded!" });
  } catch (err) {
    console.error("❌ Database Error:", err);
    res.status(500).json({ message: "Database error while inserting complaint." });
  }
});

// ---------- ADD APPOINTMENT (FIXED to use async/await) ----------
app.post("/add-appointment", async (req, res) => {
  const { reason, date, time, user_id, user_name } = req.body;

  if (!reason || !date || !time) {
    return res.status(400).json({ message: "Please fill all fields." });
  }

  if (!user_id || !user_name) {
    return res.status(400).json({ message: "You must be logged in to schedule an appointment" });
  }

  try {
    const sql = "INSERT INTO appointments (reason, date, time, user_id, user_name) VALUES (?, ?, ?, ?, ?)";
    const [result] = await db.query(sql, [reason, date, time, user_id || null, user_name || null]);

    console.log("✅ Appointment successfully recorded:", result);
    res.json({ message: "Appointment successfully recorded!" });
  } catch (err) {
    console.error("❌ Database Error:", err);
    res.status(500).json({ message: "Database insert error." });
  }
});

// ---------- 🧩 UPDATE PROFILE (FIXED to use async/await) ----------
app.post("/update-profile", async (req, res) => {
  const { id, name, email, address, contact } = req.body;

  console.log("📥 Received profile update:", req.body);

  try {
    // 1. Update users table
    const sqlUser = "UPDATE users SET name=?, email=?, address=?, contact=? WHERE id=?";
    await db.query(sqlUser, [name, email, address, contact, id]);

    // 2. Sync complaints
    const sqlComplaints = "UPDATE complaints SET user_name=?, contact=? WHERE user_id=?";
    await db.query(sqlComplaints, [name, contact, id]);

    // 3. Sync appointments
    const sqlAppointments = "UPDATE appointments SET user_name=? WHERE user_id=?";
    await db.query(sqlAppointments, [name, id]);

    res.json({ success: true, message: "Profile and related data updated successfully!" });
  } catch (err) {
    console.error("❌ Database Error (update-profile):", err);
    res.status(500).json({ message: "Server error while updating profile." });
  }
});


//----------------- ADMIN SIDE ---------------------
// ✅ Latest data (Now stable due to mysql2/promise)
app.get("/api/latest-data", async (req, res) => {
  try {
    const [complaints] = await db.query(`
      SELECT
        id, user_name, personToReport, details, incident_type, status, date, time
      FROM complaints
      ORDER BY created_at DESC
      LIMIT 5
    `);
    const [appointments] = await db.query(`
      SELECT
        id, user_name, reason, status, date, time
      FROM appointments
      ORDER BY created_at DESC
      LIMIT 5
    `);
    res.json({ complaints, appointments });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// --- 🔹 HISTORY FROM LANDING PAGE (FIXED to use async/await) ---
app.get("/api/complaints/user/:id", async (req, res) => {
  try {
    const sql = "SELECT * FROM complaints WHERE user_id = ?";
    const [data] = await db.query(sql, [req.params.id]);
    res.json(data);
  } catch (err) {
    res.status(500).json(err);
  }
});

app.get("/api/appointments/user/:id", async (req, res) => {
  try {
    const sql = "SELECT * FROM appointments WHERE user_id = ?";
    const [data] = await db.query(sql, [req.params.id]);
    res.json(data);
  } catch (err) {
    res.status(500).json(err);
  }
});

// ✅ Get all complaints (for Admin Dashboard)
app.get("/api/complaints", async (req, res) => {
  try {
    const sql = "SELECT * FROM complaints ORDER BY created_at DESC";
    const [results] = await db.query(sql);
    res.json(results);
  } catch (err) {
    console.error("Error fetching complaints:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// ✅ Get all appointments (for Admin Dashboard)
app.get("/api/appointments", async (req, res) => {
  try {
    const sql = "SELECT * FROM appointments ORDER BY created_at DESC";
    const [results] = await db.query(sql);
    res.json(results);
  } catch (err) {
    console.error("Error fetching appointments:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// ✅ Get all users (for Admin Dashboard) (FIXED to use async/await)
app.get("/api/users", async (req, res) => {
  try {
    const sql = "SELECT id, name, email, user_type, status FROM users";
    const [results] = await db.query(sql);
    res.json(results);
  } catch (err) {
    console.error("Error fetching users:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// ✅ Update user status (FIXED to use async/await)
app.put("/api/users/:id", async (req, res) => {
  try {
    const { status } = req.body;
    const sql = "UPDATE users SET status = ? WHERE id = ?";
    await db.query(sql, [status, req.params.id]);
    res.json({ success: true, message: "User status updated successfully!" });
  } catch (err) {
    console.error("Error updating user status:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// ✅ Update status route (for complaints and appointments) (FIXED to use async/await)
app.post("/update-status", async (req, res) => {
  const { type, id, status } = req.body;
  console.log("🛰 Received update request:", req.body);

  let table = "";
  if (type === "complaint") table = "complaints";
  else if (type === "appointment") table = "appointments";
  else return res.status(400).json({ message: "Invalid type." });

  const sql = `UPDATE ${table} SET status = ? WHERE id = ?`;
  console.log("🔧 Running SQL:", sql, [status, id]);

  try {
    await db.query(sql, [status, id]);

    console.log(`✅ ${type} ID=${id} updated to ${status}`);
    res.json({ message: `${type} updated to ${status} successfully!` });
  } catch (err) {
    console.error("❌ Error updating status:", err);
    res.status(500).json({ message: "Database error" });
  }
});

// ✅ Get approved complaints (FIXED to use async/await)
app.get("/api/approvedComplaints", async (req, res) => {
  try {
    const sql = "SELECT * FROM complaints WHERE status = 'Approved' ORDER BY date DESC";
    const [results] = await db.query(sql);
    res.json(results);
  } catch (err) {
    console.error("Error fetching approved complaints:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// ✅ Get approved appointments (FIXED to use async/await)
app.get("/api/approvedAppointments", async (req, res) => {
  try {
    const sql = "SELECT * FROM appointments WHERE status = 'Approved' ORDER BY date DESC";
    const [results] = await db.query(sql);
    res.json(results);
  } catch (err) {
    console.error("Error fetching approved appointments:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// ---------- CHANGE PASSWORD (FIXED to use async/await) ----------
app.post("/api/change-password", async (req, res) => {
  const { email, currentPassword, newPassword } = req.body;

  if (!email || !currentPassword || !newPassword) {
    return res.status(400).json({ message: "Please fill in all fields." });
  }

  try {
    const sql = "SELECT * FROM users WHERE email = ?";
    const [results] = await db.query(sql, [email]);

    if (results.length === 0) {
      return res.status(404).json({ message: "User not found." });
    }

    const user = results[0];

    // Compare current password
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Current password is incorrect." });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    const updateSql = "UPDATE users SET password = ? WHERE email = ?";
    await db.query(updateSql, [hashedPassword, email]);

    res.json({ message: "✅ Password updated successfully! Please log in again." });
  } catch (err) {
    console.error("Server/Database error in change-password:", err);
    res.status(500).json({ message: "Server error." });
  }
});

// ✅ Run server
const PORT = 8081;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});