require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const authRoutes = require('./routes/authRoutes');
const passwordRoutes = require('./routes/passwordRoutes');
const db = require('./config/db');

const app = express();

// Middleware
app.use(cors()); // Allow cross-origin requests
app.use(bodyParser.json());

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/passwords', passwordRoutes);

// Test Database Connection
db.execute('SELECT 1')
    .then(() => console.log('Database connected successfully'))
    .catch((err) => console.error(' Database connection error:', err));

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(` Server running on port ${PORT}`);
});
