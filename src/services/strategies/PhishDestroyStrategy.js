// src/services/strategies/PhishDestroyStrategy.js
const ThreatStrategy = require('./ThreatStrategy');

class PhishDestroyStrategy extends ThreatStrategy {
    async analyze(urlToAnalyze) {
        console.log(`🎣 [PhishDestroy] Buscando campañas de phishing para: ${urlToAnalyze}`);

        try {
            // Extraemos el dominio para pasarlo más limpio a la API
            const parsedUrl = new URL(urlToAnalyze);
            const domain = parsedUrl.hostname;

            // Endpoint exacto de la documentación (sin necesidad de API Key)
            const apiUrl = `https://api.destroy.tools/v1/check?domain=${domain}`;

            const response = await fetch(apiUrl, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json'
                }
            });

            if (!response.ok) {
                throw new Error(`Error en API de PhishDestroy: ${response.status}`);
            }

            const data = await response.json();

            // Usamos directamente el booleano 'threat' y el 'risk_score' nativo de la API
            if (data.threat) {
                return {
                    detected: true,
                    risk_score: data.risk_score || 85,
                    severity: data.severity || 'high',
                    api_flags: data.flags || [],
                    matched_keywords: data.matched_keywords || []
                };
            } else {
                return {
                    detected: false,
                    risk_score: data.risk_score || 0
                };
            }

        } catch (error) {
            console.error("❌ [PhishDestroy] Error en la consulta:", error.message);
            // Devolvemos el error en formato seguro para el Mega JSON
            return { error: error.message };
        }
    }
}

module.exports = PhishDestroyStrategy;