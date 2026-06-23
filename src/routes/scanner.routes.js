// src/routes/scanner.routes.js
const express = require('express');
const router = express.Router();

// Importamos los dos controladores
const { verifyUrl } = require('../controllers/scanner.controller.js');
const { getHistoryReport } = require('../controllers/analytics.controller.js'); // <-- ¡Aquí traemos la nueva función!

// ==========================================
// MIDDLEWARES LOCALES
// ==========================================

const validateUrlInput = (req, res, next) => {
    const { url } = req.body;
    
    if (!url || typeof url !== 'string' || url.trim() === '') {
        return res.status(400).json({ 
            success: false,
            error: "Formato inválido. Debes proporcionar un string 'url' en el body." 
        });
    }

    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        return res.status(400).json({ 
            success: false,
            error: "La URL debe incluir el protocolo (http:// o https://)." 
        });
    }

    next();
};

// ==========================================
// DEFINICIÓN DE RUTAS
// ==========================================

// 1. Ruta principal del escáner (arreglada a /scan)
router.post('/scan', validateUrlInput, verifyUrl);

// 2. Ruta para el reporte ejecutivo con IA 
router.get('/analytics/report', getHistoryReport);

module.exports = router;