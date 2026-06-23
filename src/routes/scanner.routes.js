// src/routes/scanner.routes.js
const express = require('express');
const router = express.Router();
const { verifyUrl } = require('../controllers/scanner.controller.js');

// ==========================================
// MIDDLEWARES LOCALES
// ==========================================

/**
 * Middleware para validar que el body contiene una URL antes de molestar al controlador.
 */
const validateUrlInput = (req, res, next) => {
    const { url } = req.body;
    
    if (!url || typeof url !== 'string' || url.trim() === '') {
        return res.status(400).json({ 
            success: false,
            error: "Formato inválido. Debes proporcionar un string 'url' en el body." 
        });
    }

    // Validación básica de estructura web (que empiece con http/https)
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        return res.status(400).json({ 
            success: false,
            error: "La URL debe incluir el protocolo (http:// o https://)." 
        });
    }

    next(); // Todo en orden, pasamos el control al controller
};

// ==========================================
// DEFINICIÓN DE RUTAS
// ==========================================

// Usamos POST /scan para respetar la especificación técnica de OnlyQRs
// Le inyectamos el validador antes de ejecutar verifyUrl
router.post('/scan', validateUrlInput, verifyUrl);

module.exports = router;