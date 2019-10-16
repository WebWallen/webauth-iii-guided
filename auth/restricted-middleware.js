const jwt = require('jsonwebtoken');
const secrets = require('../config/secrets');

module.exports = (req, res, next) => {
  const token = req.headers.authorization;

  if (token) {
    // Check that token is valid
    jwt.verify(token, secrets.jwtSecret, (err, decodedToken) => {
      if (err) {
        // Foul play
        res.status(401).json({ message: 'Invalid Credentials' });
      } else {
        // Token = good
          req.user = { 
            username: decodedToken.username, 
            role: decodedToken.role
          };
          next();
      }
    })    
  } else {
    res.status(400).json({ message: 'No token provided' });
  }
}