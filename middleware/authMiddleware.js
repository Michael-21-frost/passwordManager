const jwt = require('jsonwebtoken');
const SECRET_KEY = process.env.JWT_SECRET;

module.exports = (req, res, next) => {
    const token = req.header('Authorization');

    if (!token) {
        return res.status(401).json({ error: 'Access denied. No token provided.' });
    }

    try {
        const decoded = jwt.verify(token.split(' ')[1], SECRET_KEY); // Extract the token after "Bearer"
        req.user = decoded; // Attach the user payload to req
        next();
    } catch (error) {
        return res.status(400).json({ error: 'Invalid token' });
    }
};
