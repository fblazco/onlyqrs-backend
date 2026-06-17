// routes/scanner.routes.js
const express = require('express');
const router = express.Router();
const { verifyUrl } = require('../controllers/scanner.controller.js');

// Cuando el frontend haga un POST a esta ruta, se ejecutará el controlador
router.post('/verify', verifyUrl);

module.exports = router;