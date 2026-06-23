// src/controllers/analytics.controller.js
const ScanHistory = require('../models/scanHistory.model');
const geminiService = require('../services/gemini.service');

const getHistoryReport = async (req, res) => {
    try {
        console.log("📊 [Analytics] Solicitando registros a PostgreSQL...");
        const registros = await ScanHistory.findAll();

        if (!registros || registros.length === 0) {
            return res.json({
                success: true,
                message: "Historial vacío. Registra algunos escaneos antes de consultar analíticas."
            });
        }

        // El servicio procesa, calcula y unifica la estructura final
        const dashboardData = await geminiService.generateHistoryAnalytics(registros);

        return res.json({
            success: true,
            ...dashboardData
        });

    } catch (error) {
        console.error("❌ [Analytics Controller] Error:", error.message);
        return res.status(500).json({
            success: false,
            error: "Error interno al procesar el dashboard consolidado."
        });
    }
};

module.exports = { getHistoryReport };