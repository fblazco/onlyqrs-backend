// src/services/strategies/AbuseStrategy.js
const ThreatStrategy = require('./ThreatStrategy');

class AbuseStrategy extends ThreatStrategy {
    async analyze(urlToAnalyze) {
        console.log(`🦠 [URLhaus] Consultando base de datos de malware para: ${urlToAnalyze}`);

        // OJO: Recuerda agregar URLHAUS_API_KEY a tu archivo .env
        const apiKey = process.env.URLHAUS_API_KEY;

        try {
            const formBody = new URLSearchParams();
            formBody.append('url', urlToAnalyze);

            // Armamos los headers incluyendo la llave requerida por la documentación
            const requestHeaders = {
                'Content-Type': 'application/x-www-form-urlencoded'
            };

            if (apiKey) {
                requestHeaders['Auth-Key'] = apiKey;
            } else {
                console.warn("⚠️ [URLhaus] Falta URLHAUS_API_KEY en el .env. La consulta podría ser rechazada.");
            }

            const response = await fetch('https://urlhaus-api.abuse.ch/v1/url/', {
                method: 'POST',
                headers: requestHeaders,
                body: formBody.toString()
            });

            if (!response.ok) {
                throw new Error(`Error en API de URLhaus: HTTP ${response.status}`);
            }

            const data = await response.json();

            // Evaluamos las respuestas exactas que indica la documentación
            if (data.query_status === 'ok') {
                return {
                    detected: true,
                    threat: data.threat || 'malware',
                    status: data.url_status || 'unknown',
                    reference: data.urlhaus_reference
                };
            } else if (data.query_status === 'no_results') {
                return {
                    detected: false,
                    threat: "NONE",
                    message: "URL no encontrada en la base de datos de malware"
                };
            } else {
                // Capturamos si la API nos dice invalid_url u otro error de sintaxis
                return {
                    detected: false,
                    message: `Respuesta de la API: ${data.query_status}`
                };
            }

        } catch (error) {
            console.error("❌ [URLhaus] Error en la consulta:", error.message);
            return { error: error.message };
        }
    }
}

module.exports = AbuseStrategy;