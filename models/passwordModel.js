//passwordModel.js
const db = require('../config/db');

class Password {
    static async savePassword(userId, serviceName, encryptedPassword) {
        const sql = 'INSERT INTO passwords (user_id, service_name, encrypted_password) VALUES (?, ?, ?)';
        return db.execute(sql, [userId, serviceName, encryptedPassword]);
    }

    static async getPasswordsByUser(userId) {
        const sql = 'SELECT * FROM passwords WHERE user_id = ? ORDER BY created_at DESC';
        const [rows] = await db.execute(sql, [userId]);
        return rows;
    }
    
}

module.exports = Password;
