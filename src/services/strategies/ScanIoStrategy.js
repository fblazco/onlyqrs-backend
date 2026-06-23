// src/services/strategies/ScanIoStrategy.js
const ThreatStrategy = require('./ThreatStrategy');

class ScanIoStrategy extends ThreatStrategy {
    async analyze(urlToAnalyze) {
        console.log(`📸 [URLScan.io] Buscando historial de escaneos para: ${urlToAnalyze}`);

        // Recuerda agregar URLSCAN_API_KEY a tu .env
        const apiKey = process.env.URLSCAN_API_KEY;

        if (!apiKey) {
            return { error: "Falta la variable URLSCAN_API_KEY" };
        }

        try {
            // Extraemos solo el dominio para buscar en el historial general de ese sitio
            const parsedUrl = new URL(urlToAnalyze);
            const domain = parsedUrl.hostname;

            // Buscamos el dominio y le pedimos solo el resultado más reciente (size=1)
            const apiUrl = `https://urlscan.io/api/v1/search/?q=domain:${domain}&size=1`;

            const response = await fetch(apiUrl, {
                method: 'GET',
                headers: {
                    'API-Key': apiKey,
                    'Content-Type': 'application/json'
                }
            });

            if (!response.ok) {
                throw new Error(`Error en API de URLScan: ${response.status}`);
            }

            const data = await response.json();

            // Si hay resultados, significa que alguien ya escaneó esta página antes
            if (data.results && data.results.length > 0) {
                const ultimoEscaneo = data.results[0];
                
                // URLScan guarda un veredicto general (malicious: true/false)
                const isMalicious = ultimoEscaneo.verdicts?.overall?.malicious || false;
                
                return {
                    found: true,
                    malicious: isMalicious,
                    score: ultimoEscaneo.verdicts?.overall?.score || 0,
                    report_url: ultimoEscaneo.result // El link para ver la foto de la página
                };
            } else {
                // El dominio es fantasma para URLScan (nunca nadie lo ha escaneado)
                return {
                    found: false,
                    malicious: false,
                    message: "Dominio desconocido para URLScan (posible Día Cero)"
                };
            }

        } catch (error) {
            console.error("❌ [URLScan] Error en la consulta:", error.message);
            return { error: error.message };
        }
    }
}

module.exports = ScanIoStrategy;