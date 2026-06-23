// src/services/strategies/VirusTotalStrategy.js
const ThreatStrategy = require('./ThreatStrategy');

class VirusTotalStrategy extends ThreatStrategy {
    async analyze(urlToAnalyze) {
        console.log(`🛡️ [VirusTotal] Consultando motores antivirus para: ${urlToAnalyze}`);

        const apiKey = process.env.VIRUSTOTAL_API_KEY;
        
        if (!apiKey) {
            return { error: "Falta la variable VIRUSTOTAL_API_KEY en .env" };
        }

        // VirusTotal v3 exige que la URL se envíe como un hash Base64 sin padding (sin signos '=')
        const urlIdBase64 = Buffer.from(urlToAnalyze).toString('base64').replace(/=/g, '');

        try {
            const response = await fetch(`https://www.virustotal.com/api/v3/urls/${urlIdBase64}`, {
                method: 'GET',
                headers: {
                    'x-apikey': apiKey
                }
            });

            // Si VT devuelve 404, significa que NADIE ha escaneado este link antes (Día Cero).
            if (response.status === 404) {
                console.log("⚠️ [VirusTotal] URL no encontrada en la base de datos (Día Cero).");
                return {
                    malicious: 0,
                    suspicious: 0,
                    harmless: 0,
                    message: "URL no encontrada en VirusTotal (Posible Día Cero)"
                };
            }

            if (!response.ok) {
                throw new Error(`Error en la API de VirusTotal: status ${response.status}`);
            }

            const vtData = await response.json();
            const stats = vtData.data.attributes.last_analysis_stats;

            // Retornamos exactamente la estructura que definiste en tu especificación técnica
            return {
                malicious: stats.malicious || 0,
                suspicious: stats.suspicious || 0,
                harmless: stats.harmless || 0
            };

        } catch (error) {
            console.error("❌ [VirusTotal] Error en la consulta:", error.message);
            // Devolvemos el error para que Promise.allSettled no estalle
            return { error: error.message };
        }
    }
}

module.exports = VirusTotalStrategy;