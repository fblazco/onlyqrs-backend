// src/controllers/scanner.controller.js

// ==========================================
// IMPORTACIONES DE ESTRATEGIAS (Rutas Corregidas)
// ==========================================
const WhoisStrategy = require('../services/strategies/WhoisStrategy');
const VirusTotalStrategy = require('../services/strategies/VirusTotalStrategy');
const HeuristicStrategy = require('../services/strategies/HeuristicStrategy');
const AbuseStrategy = require('../services/strategies/AbuseStrategy');
const GoogleSBStrategy = require('../services/strategies/GoogleSBStrategy');
const PhishDestroyStrategy = require('../services/strategies/PhishDestroyStrategy');
const ScanIoStrategy = require('../services/strategies/ScanIoStrategy');
const ScanHistory = require('../models/scanHistory.model');
// ==========================================
// IMPORTACIONES DE SERVICIOS
// ==========================================
const scoringService = require('../services/scoring.service');
const geminiService = require('../services/gemini.service');

async function verifyUrl(req, res) {
    try {
        const { url } = req.body;
        
        if (!url) {
            return res.status(400).json({ error: "Falta URL" });
        }

        // 🚨 1. EL MOCK DE DESARROLLO (Cortocircuito)
        if (url.includes("hacker-page.com")) {
            console.log("😈 Simulacro activado para hacker-page.com");
            return res.json({
                score: 95,
                riskLevel: "CRITICAL",
                summary: "Este código QR dirige a un sitio con múltiples indicadores de phishing. El dominio fue creado recientemente y aparece reportado por varios servicios de seguridad. Se recomienda no abrir el enlace.",
                flags: [
                    "young_domain",
                    "blacklisted",
                    "fake_login",
                    "suspicious_tld",
                    "malicious_reports"
                ],
                details: { mock: true }
            });
        }

        console.log(`🔍 Iniciando análisis en paralelo para: ${url}`);

        // 🚀 2. INICIALIZAR ESTRATEGIAS
        // Aquí puedes ir descomentando las demás a medida que programes su método analyze()
        const strategies = [
            new HeuristicStrategy(),
            new WhoisStrategy(),
            new VirusTotalStrategy(),
            new GoogleSBStrategy(),
            new ScanIoStrategy(),
            new AbuseStrategy(),
            new PhishDestroyStrategy()
        ];

        // ⚡ 3. EJECUTAR EN PARALELO
        // Mapeamos cada estrategia para que ejecute su método analyze()
        const promises = strategies.map(strategy => strategy.analyze(url));
        
        // allSettled garantiza que si se cae una API, el resto sigue funcionando
        const results = await Promise.allSettled(promises);

        // 🧩 4. ARMAR EL MEGA JSON
        const megaJson = { url };
        results.forEach((result, index) => {
            const strategyName = strategies[index].constructor.name.replace('Strategy', '').toLowerCase();
            
            // Si la promesa se cumplió, guardamos la data. Si falló, guardamos el error para los logs.
            if (result.status === 'fulfilled') {
                megaJson[strategyName] = result.value;
            } else {
                console.error(`❌ Error en motor ${strategyName}:`, result.reason);
                megaJson[strategyName] = { error: "Motor falló o time-out", details: result.reason };
            }
        });

        // ⚖️ 5. CALCULAR RIESGO MATEMÁTICO
        const finalAssessment = scoringService.calculateRisk(megaJson);

        // 🤖 6. GENERAR RESUMEN CON GEMINI
        // Le pasamos los datos duros a la IA para que los traduzca a lenguaje humano
        const aiSummary = await geminiService.generateSummary(
            finalAssessment.score, 
            finalAssessment.riskLevel, 
            finalAssessment.flags
        );

        // 💾 7. (Opcional) Aquí irá el código de Sequelize para guardar en PostgreSQL
        await ScanHistory.create({
            url: url,
            score: finalAssessment.score,
            riskLevel: finalAssessment.riskLevel,
            summary: aiSummary,
            flags: finalAssessment.flags,
            details: megaJson // El objeto con todo el análisis de los motores
        });
        // 📤 8. RESPUESTA FINAL AL FRONTEND
        return res.json({
            score: finalAssessment.score,
            riskLevel: finalAssessment.riskLevel,
            summary: aiSummary,
            details: megaJson
        });

    } catch (error) {
        console.error("🔥 Error crítico en el escáner central:", error);
        return res.status(500).json({ error: "Error interno en el escáner central." });
    }
}

module.exports = { verifyUrl };