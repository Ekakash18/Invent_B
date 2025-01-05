import jwt from 'jsonwebtoken';
import { apiKeysStore } from './apiKey.utils.js'; // Import your apiKeysStore or replace with actual path

export const authenticateToken = (req, res, next) => {
    const authHeader = req.header('Authorization');
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access denied, no token provided' });
    }

    try {
        // Verify the token with the retrieved secret key
        const decoded = jwt.verify(token, "bd0d6fc93d5eef504c4a0437cd7b97ed23d0043fbe2a3e6c303cef26fbbe49ac");
        console.log(decoded);
        req.user = decoded; // Attach decoded token to request object
        next(); // Proceed to the next middleware or route
    } catch (err) {
        // Handle specific JWT errors for better debugging
        if (err.name === 'TokenExpiredError') {
            res.status(401).json({ error: 'Token has expired' });
        } else if (err.name === 'JsonWebTokenError') {
            res.status(403).json({ error: 'Invalid token' });
        } else {
            res.status(500).json({ error: 'Internal server error' });
        }
    }
};
