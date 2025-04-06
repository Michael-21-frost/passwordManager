const crypto = require('crypto');
const bcrypt = require('bcrypt');
const Password = require('../models/passwordModel');

const ENCRYPTION_KEY = Buffer.from(process.env.ENCRYPTION_KEY, 'hex'); // Convert from hex
const IV_LENGTH = 16;

if (!ENCRYPTION_KEY || ENCRYPTION_KEY.length !== 32) {
  console.error('Encryption key must be exactly 32 bytes (64 hex characters in .env)');
  process.exit(1);
}

// AES-256 Encryption
function encrypt(text) {
    try {
        let iv = crypto.randomBytes(IV_LENGTH);
        let cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
        let encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);

        return iv.toString('hex') + ':' + encrypted.toString('hex');
    } catch (error) {
        console.error('Encryption error:', error);
        throw new Error('Encryption failed');
    }
}

// AES-256 Decryption
function decrypt(text) {
    try {
        let parts = text.split(':');
        if (parts.length !== 2) {
            throw new Error('Invalid encrypted format');
        }

        let iv = Buffer.from(parts[0], 'hex');
        let encryptedText = Buffer.from(parts[1], 'hex');
        let decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
        
        return Buffer.concat([decipher.update(encryptedText), decipher.final()]).toString();
    } catch (error) {
        console.error('Decryption error:', error);
        throw new Error('Decryption failed');
    }
}

// **Hash Password (New Function)**
exports.hashPassword = async (req, res) => {
    try {
        const { password } = req.body;

        if (!password) {
            return res.status(400).json({ error: 'Password is required' });
        }

        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        res.json({ hashedPassword });
    } catch (error) {
        console.error('Hashing error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
};

// Save Password
exports.savePassword = async (req, res) => {
    try {
        const { userId } = req.user;
        const { serviceName, password } = req.body;

        if (!userId || !serviceName || !password) {
            return res.status(400).json({ error: 'User ID, service name, and password are required' });
        }

        const encryptedPassword = encrypt(password);
        await Password.savePassword(userId, serviceName, encryptedPassword);

        res.status(201).json({ message: 'Password saved securely' });
    } catch (error) {
        console.error('Save password error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
};

// Retrieve Passwords
exports.getPasswords = async (req, res) => {
    try {
        const { userId } = req.user;

        if (!userId) {
            return res.status(400).json({ error: 'User ID is required' });
        }

        const passwords = await Password.getPasswordsByUser(userId);
        if (!passwords.length) {
            return res.status(404).json({ error: 'No passwords found' });
        }

        const decryptedPasswords = passwords.map(p => {
            try {
                return {
                    id: p.id,
                    serviceName: p.service_name,
                    password: decrypt(p.encrypted_password),
                };
            } catch (error) {
                console.error(`Decryption failed for password ID ${p.id}:`, error);
                return { id: p.id, serviceName: p.service_name, password: 'Decryption error' };
            }
        });

        res.json(decryptedPasswords);
    } catch (error) {
        console.error('Get passwords error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
};
