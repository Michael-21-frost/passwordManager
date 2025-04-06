//userModel.js
const db = require('../config/db');

class User {
    static async createUser(email, passwordHash) {
        const sql = 'INSERT INTO users (email, password_hash) VALUES (?, ?)';
        return db.execute(sql, [email, passwordHash]);
    }

    static async findByEmail(email) {
        const sql = 'SELECT * FROM users WHERE email = ?';
        const [rows] = await db.execute(sql, [email]);
        return rows.length ? rows[0] : null;
    }

    static async update2FA(userId, secret) {
        const sql = 'UPDATE users SET two_fa_secret = ? WHERE id = ?';
        return db.execute(sql, [secret, userId]);
    }

    static async get2FASecret(userId) {
        const sql = 'SELECT two_fa_secret FROM users WHERE id = ?';
        const [rows] = await db.execute(sql, [userId]);
        return rows.length ? rows[0].two_fa_secret : null;
    }
}

module.exports = User;
