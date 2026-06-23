// src/services/strategies/AbuseStrategy.js
const ThreatStrategy = require('./ThreatStrategy');

class AbuseStrategy extends ThreatStrategy {
    async analyze(urlToAnalyze) {
        console.log(`🦠 [URLhaus] Consultando base de datos de malware para: ${urlToAnalyze}`);

        try {
            // URLhaus requiere que los parámetros vayan como un formulario tradicional
            const formBody = new URLSearchParams();
            formBody.append('url', urlToAnalyze);

            const response = await fetch('https://urlhaus-api.abuse.ch/v1/url/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: formBody.toString()
            });

            if (!response.ok) {
                throw new Error(`Error en API de URLhaus: ${response.status}`);
            }

            const data = await response.json();

            // URLhaus devuelve query_status "ok" si la URL está en su lista negra de malware
            if (data.query_status === 'ok') {
                return {
                    detected: true,
                    threat: data.threat || 'malware',
                    status: data.url_status || 'unknown', // Devuelve "online" o "offline"
                    reference: data.urlhaus_reference
                };
            } else {
                // Si la URL está limpia o no la conocen, devuelven "no_results"
                return {
                    detected: false,
                    threat: "NONE"
                };
            }

        } catch (error) {
            console.error("❌ [URLhaus] Error en la consulta:", error.message);
            // Devolvemos el error para que el Promise.allSettled lo maneje sin botar el resto
            return { error: error.message };
        }
    }
}

module.exports = AbuseStrategy;