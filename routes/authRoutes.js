//authRoutes.js
const express = require('express');
const { register, login, enable2FA, verify2FA} = require('../controllers/authController');
const authMiddleware = require('../middleware/authMiddleware');
const router = express.Router();

router.post('/register', register);
router.post('/login', login);
router.post('/enable-2fa', enable2FA);
router.post('/verify-2fa', authMiddleware, verify2FA)

module.exports = router;
