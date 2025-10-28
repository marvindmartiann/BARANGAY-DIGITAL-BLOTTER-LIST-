const express = require("express");
const mysql = require("mysql2/promise"); 
const cors = require("cors");
const bcrypt = require("bcrypt");
const path = require("path");

const app = express();
app.use(cors());
app.use(express.json());

// Serve frontend files from parent directory
app.use(express.static(path.join(__dirname, "..")));

// -------------------------------------------------------------------
// UPDATED DATABASE CONNECTION BLOCK
// -------------------------------------------------------------------
let db;

async function initializeDatabaseConnection() {
    const dbConfig = {
        host: "localhost",
        user: "root",
        password: "", // XAMPP default
        database: "barangay_blotter",
    };

    // 1. Try default MySQL port (3306)
    try {
        console.log("Attempting connection to MySQL on port 3306...");
        db = mysql.createPool({ ...dbConfig, port: 3306 });
        const connection = await db.getConnection();
        console.log("✅ Connected to MySQL Database (using Pool) on port 3306!");
        connection.release();
        return; 
    } catch (err) {
        console.warn("Connection attempt on port 3306 failed. Trying port 3307...");
    }

    // 2. Try alternative MySQL port (3307)
    try {
        db = mysql.createPool({ ...dbConfig, port: 3307 });
        const connection = await db.getConnection();
        console.log("✅ Connected to MySQL Database (using Pool) on port 3307!");
        connection.release();
        return; 
    } catch (err) {
        console.error("Database connection failed on both ports 3306 and 3307:", err.message);
        // Throw the final error to prevent the server from fully starting without DB access
        throw err;
    }
}

// -------------------------------------------------------------------
// Wrap server setup in an async function to wait for DB connection
// -------------------------------------------------------------------

async function startServer() {
    try {
        await initializeDatabaseConnection();

        // ---------------------------------------------------------------------
        // -------------------------- USER ROUTES ------------------------------
        // ---------------------------------------------------------------------

        // ---------- REGISTER ----------
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

       // server.js (Partial Code)

// ---------- GENERIC LOGIN (CORRECTED: Blocks officials and Inactive Users) ----------
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
        const userType = user.user_type ? user.user_type.toLowerCase() : null;

        // 🔍 DEBUGGING: I-print ang status para ma-verify mo sa console
        console.log(`User ID: ${user.id} attempting login. Status from DB: ${user.status}`);
        
        // 🛑 FIX: CRITICAL CHECK for INACTIVE STATUS
        // Ginawa kong case-insensitive check (toLowerCase()) para sigurado
        if (user.status && user.status.toLowerCase() === 'inactive') { 
            console.warn(`🛑 Inactive user login attempt blocked for: ${email}`);
            return res.status(403).json({ 
                message: "Access denied: Your account is inactive. Please contact the Admin.",
                user_type: user.user_type
            });
        }
        
        // 🛑 CORRECTION: Block officials from using the resident login endpoint
        if (userType === 'official') {
            console.warn(`🛑 Official login attempt blocked at /login by: ${email}`);
            return res.status(403).json({ 
                message: "Access denied: You are an Official. Please use the designated Admin Login page.",
                user_type: user.user_type
            });
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(401).json({ message: "Invalid email or password." });
        }

        // Success: Return the resident user's data
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

        // ---------- ADMIN LOGIN (Used by Admin Login Page: adminlogin.html) ----------
        app.post("/admin/login", async (req, res) => {
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

                const userType = user.user_type ? user.user_type.toLowerCase() : null; 
                
                if (userType !== 'official') {
                    console.warn(`🛑 Unauthorized admin login attempt by user: ${email} (Type: ${userType})`);
                    return res.status(403).json({ message: "Access denied: You are not authorized for the Admin portal." });
                }

                // Success for Official User
                res.json({
                    message: "Admin Login successful!",
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
                console.error("❌ CRITICAL SERVER ERROR during admin login:", err);
                
                let errorMessage = "Server error during login.";
                if (err.code === 'ECONNREFUSED' || err.code === 'PROTOCOL_CONNECTION_LOST') {
                    errorMessage = "Server failed to connect to the database. Please check MySQL/XAMPP.";
                }
                
                res.status(500).json({ message: errorMessage });
            }
        });

        // ---------- ADD COMPLAINT (FIXED) ----------
app.post("/add-complaint", async (req, res) => {
    console.log("📥 Received complaint data:", req.body);
    
    const user_id = req.body.user_id;
    const user_name = req.body.user_name;
    const contact = req.body.contact;
    const date = req.body.date;
    const time = req.body.time;
    const personToReport = req.body.personToReport;
    const incident_type = req.body.incidentType; 
    const details = req.body.details;

    if (!user_id || !user_name || !contact || !date || !time || !personToReport || !incident_type || !details) {
        console.error("❌ Missing fields in request body:", req.body);
        return res.status(400).json({ message: "Please fill out all required fields." });
    }

    try {
        const sql = `
    INSERT INTO complaints (user_id, user_name, contact, date, time, personToReport, incident_type, details)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
`;
        const [result] = await db.query(sql, [user_id, user_name, contact, date, time, personToReport, incident_type, details]);

        console.log("✅ Complaint successfully recorded:", result);
        res.json({ message: "Complaint successfully recorded!" });
    } catch (err) {
        console.error("❌ Database Error:", err.message || err); 
        console.error(err); 
        
        res.status(500).json({ message: "Database error while inserting complaint." });
    }
});

        // ---------- ADD APPOINTMENT ----------
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
        
        // ---------------------------------------------------------------------
        // UPDATE PROFILE ROUTE (SAVE CHANGES)
        // ---------------------------------------------------------------------
        app.put("/api/users/:id/update-profile", async (req, res) => {
            // Get ID from URL parameter and fields from the request body
            const userId = req.params.id; 
            const { name, address, contact } = req.body; 

            console.log(`📥 Received profile update for User ID ${userId}:`, req.body);

            // Basic validation
            if (!name || !address || !contact) {
                return res.status(400).json({ message: "All profile fields are required." });
            }

            try {
                // 1. Update users table
                const sqlUser = "UPDATE users SET name=?, address=?, contact=? WHERE id=?";
                const [userResult] = await db.query(sqlUser, [name, address, contact, userId]);

                if (userResult.affectedRows === 0) {
                    return res.status(404).json({ message: "User not found or no changes applied." });
                }

                // 2. Sync complaints 
                const sqlComplaints = "UPDATE complaints SET user_name=?, contact=? WHERE user_id=?";
                await db.query(sqlComplaints, [name, contact, userId]);

                // 3. Sync appointments
                const sqlAppointments = "UPDATE appointments SET user_name=? WHERE user_id=?";
                await db.query(sqlAppointments, [name, userId]);

                res.json({ success: true, message: "Profile and related data updated successfully!" });
            } catch (err) {
                console.error("❌ Database Error (update-profile):", err);
                res.status(500).json({ message: "Server error while updating profile." });
            }
        });

        // --- 🔹 HISTORY FROM LANDING PAGE ---
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

        // ---------------------------------------------------------------------
        // CHANGE PASSWORD ROUTE
        // ---------------------------------------------------------------------
        app.post("/api/users/:id/change-password", async (req, res) => {
            const userId = req.params.id; // Get ID from URL
            const { currentPassword, newPassword } = req.body; 

            if (!currentPassword || !newPassword) {
                return res.status(400).json({ message: "Please fill in current and new passwords." });
            }

            try {
                // 1. Find the user by ID
                const sql = "SELECT * FROM users WHERE id = ?";
                const [results] = await db.query(sql, [userId]);

                if (results.length === 0) {
                    return res.status(404).json({ message: "User not found." });
                }

                const user = results[0];

                // 2. Compare current password
                const isMatch = await bcrypt.compare(currentPassword, user.password);
                if (!isMatch) {
                    // Log the attempt but return a generic error for security
                    console.warn(`🛑 Failed password change for ID ${userId}: current password mismatch.`);
                    return res.status(401).json({ message: "Current password is incorrect." });
                }

                // 3. Hash the new password
                const hashedPassword = await bcrypt.hash(newPassword, 10);

                // 4. Update the password
                const updateSql = "UPDATE users SET password = ? WHERE id = ?";
                await db.query(updateSql, [hashedPassword, userId]);

                res.json({ message: "✅ Password updated successfully! Please log in again." });
            } catch (err) {
                console.error("Server/Database error in change-password:", err);
                res.status(500).json({ message: "Server error." });
            }
        });
        
        // ---------------------------------------------------------------------
        // -------------------------- ADMIN ROUTES -----------------------------
        // ---------------------------------------------------------------------

        // Latest data (for Admin Dashboard)
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

        // Get all complaints (for Admin Dashboard)
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

        // Get all appointments (for Admin Dashboard)
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

        // Get all users (for Admin Dashboard)
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

        // Update user status
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

        // Update status route (for complaints and appointments)
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

        // Get approved complaints
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

        // Get approved appointments
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


        // Run server
        const PORT = 8081;
        app.listen(PORT, () => {
            console.log(`🚀 Server running on port ${PORT}`);
        });

    } catch (dbErr) {
        // This catches the final error if both 3306 and 3307 fail
        console.error("🛑 FAILED TO START SERVER: Database connection could not be established on multiple ports.", dbErr.message);
        process.exit(1); // Exit the application
    }
}

// Start the whole application
startServer();