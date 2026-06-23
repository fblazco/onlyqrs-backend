// src/services/strategies/GoogleSBStrategy.js
const ThreatStrategy = require('./ThreatStrategy');

class GoogleSBStrategy extends ThreatStrategy {
    async analyze(urlToAnalyze) {
        console.log(`🔍 [GoogleSB] Consultando base de datos de Google para: ${urlToAnalyze}`);

        // OJO: Acuérdate de agregar GOOGLE_SB_API_KEY a tu archivo .env y en Render
        const apiKey = process.env.GOOGLE_SB_API_KEY;

        if (!apiKey) {
            return { error: "Falta la variable GOOGLE_SB_API_KEY" };
        }

        const apiUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;

        // Estructura exacta que exige Google v4
        const payload = {
            client: {
                clientId: "onlyqrs-backend",
                clientVersion: "1.0.0"
            },
            threatInfo: {
                // Buscamos Malware, Phishing (Social Engineering) y Software no deseado
                threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                platformTypes: ["ANY_PLATFORM"],
                threatEntryTypes: ["URL"],
                threatEntries: [
                    { url: urlToAnalyze }
                ]
            }
        };

        try {
            const response = await fetch(apiUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(payload)
            });

            if (!response.ok) {
                throw new Error(`Error en API de Google: ${response.status}`);
            }

            const data = await response.json();

            // Si Google encuentra amenazas, devuelve un array "matches". 
            // Si la URL es segura, devuelve un objeto vacío {}.
            if (data.matches && data.matches.length > 0) {
                // Tomamos la primera amenaza reportada
                const primaryThreat = data.matches[0];
                
                return {
                    detected: true,
                    threatType: primaryThreat.threatType,
                    raw_matches: data.matches // Guardamos todo por si acaso
                };
            } else {
                return {
                    detected: false,
                    threatType: "NONE"
                };
            }

        } catch (error) {
            console.error("❌ [GoogleSB] Error en la consulta:", error.message);
            return { error: error.message };
        }
    }
}

module.exports = GoogleSBStrategy;