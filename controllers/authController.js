//authController.js
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const User = require('../models/userModel');

const SECRET_KEY = process.env.JWT_SECRET;

// User Registration
exports.register = async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        const existingUser = await User.findByEmail(email);
        if (existingUser) {
            return res.status(400).json({ error: 'Email already registered' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        await User.createUser(email, hashedPassword);
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
};

// User Login

exports.login = async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        const user = await User.findByEmail(email);
        if (!user || !(await bcrypt.compare(password, user.password_hash))) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const token = jwt.sign({ userId: user.id, email: user.email }, SECRET_KEY, { expiresIn: '1h' });

        res.json({
            message: 'Login successful',
            token,
            user: { id: user.id, email: user.email } //  Return user email
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
};


// Enable 2FA
exports.enable2FA = async (req, res) => {
  try {
      console.log('Request user:', req.user); // Debugging
      if (!req.user) {
          return res.status(401).json({ error: 'Unauthorized. No user found.' });
      }

      const { userId } = req.user;
      if (!userId) {
          return res.status(400).json({ error: 'User ID is required' });
      }

      const secret = speakeasy.generateSecret({ length: 20 });

      await User.update2FA(userId, secret.base32);

      const otpAuthUrl = `otpauth://totp/PasswordManager:${userId}?secret=${secret.base32}&issuer=PasswordManager`;

      QRCode.toDataURL(otpAuthUrl, (err, qrCode) => {
          if (err) {
              console.error('QR Code generation error:', err);
              return res.status(500).json({ error: 'QR Code generation failed' });
          }

          res.json({
              message: '2FA enabled',
              secret: secret.base32,
              qrCode
          });
      });
  } catch (error) {
      console.error('Enable 2FA error:', error);
      res.status(500).json({ error: 'Internal server error' });
  }
};


// Verify 2FA Code
exports.verify2FA = async (req, res) => {
    try {
        const { userId, token } = req.body;
        if (!userId || !token) {
            return res.status(400).json({ error: 'User ID and token are required' });
        }

        const secret = await User.get2FASecret(userId);
        if (!secret) {
            return res.status(400).json({ error: '2FA not enabled for this user' });
        }

        const verified = speakeasy.totp.verify({
            secret,
            encoding: 'base32',
            token
        });

        if (!verified) {
            return res.status(401).json({ error: 'Invalid OTP' });
        }

        res.json({ message: '2FA verification successful' });
    } catch (error) {
        console.error('2FA verification error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
};
