// src/services/strategies/WhoisStrategy.js
const ThreatStrategy = require('./ThreatStrategy');

class WhoisStrategy extends ThreatStrategy {
    async analyze(urlToAnalyze) {
        console.log(`📅 [Whois] Verificando antigüedad del dominio para: ${urlToAnalyze}`);

        const apiKey = process.env.WHOIS_API_KEY;
        
        if (!apiKey) {
            return { error: "Falta la variable WHOIS_API_KEY en .env" };
        }

        try {
            // Solo necesitamos el dominio raíz (ej: banco.com) para consultar el Whois
            const parsedUrl = new URL(urlToAnalyze);
            const domain = parsedUrl.hostname;

            const options = {
                method: 'GET',
                url: `https://whoisjson.com/api/v1/whois?domain=${domain}`,
                headers: {
                    'Authorization': `TOKEN=${apiKey}`
                }
            };

            const response = await fetch(options.url, {
                method: options.method,
                headers: options.headers
            });

            if (!response.ok) {
                throw new Error(`Error en API de WhoisJSON: ${response.status}`);
            }

            const data = await response.json();

            // WhoisJSON a veces manda la fecha en distintas propiedades dependiendo del registrador
            const fechaCreacion = data.created || data.creation_date || (data.domain && data.domain.created_date);

            if (fechaCreacion) {
                const creationDate = new Date(fechaCreacion);
                const hoy = new Date();
                
                // Calculamos la diferencia en días
                const edadDias = Math.floor((hoy - creationDate) / (1000 * 60 * 60 * 24));

                return {
                    found: true,
                    age_in_days: edadDias,
                    creation_date: creationDate.toISOString().split('T')[0]
                };
            } else {
                return {
                    found: false,
                    message: "No se pudo obtener la fecha de creación del dominio."
                };
            }

        } catch (error) {
            console.error("❌ [Whois] Error en la consulta:", error.message);
            return { error: error.message };
        }
    }
}

module.exports = WhoisStrategy;