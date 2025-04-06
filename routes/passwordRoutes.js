//passwordRoutes.js
const express = require('express');
const router = express.Router();
const { savePassword, getPasswords, hashPassword } = require('../controllers/passwordController');  //  Ensure correct import

const authMiddleware = require('../middleware/authMiddleware');

router.post('/save-password', authMiddleware, savePassword);
router.get('/get-passwords', authMiddleware, getPasswords);
router.post('/hash-password', hashPassword); 

module.exports = router;



