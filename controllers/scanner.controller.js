// controllers/scanner.controller.js
const { URL } = require('url');

async function verifyUrl(req, res) {
    try {
        const { url } = req.body;

        if (!url) {
            return res.status(400).json({ 
                success: false, 
                message: "Debes enviar una URL para analizar." 
            });
        }

        console.log(`🔍 Generando informe de seguridad para: ${url}`);

        // ==========================================
        // 1. LIMPIAR LA URL
        // ==========================================
        let domain;
        try {
            const parsedUrl = new URL(url);
            domain = parsedUrl.hostname; 
        } catch (err) {
            return res.status(400).json({ 
                success: false, 
                message: "El formato de la URL no es válido." 
            });
        }

        // ==========================================
        // 2. CONSULTA A LA API DE WHOISJSON
        // ==========================================
        const apiKey = process.env.WHOIS_API_KEY;
        
        if (!apiKey) {
            throw new Error("Falta la variable WHOIS_API_KEY en Render");
        }

        // Armamos la configuración exacta que me pasaste
        const options = {
            method: 'GET',
            url: 'https://whoisjson.com/api/v1/whois',
            params: { domain: domain },
            headers: {
                'Authorization': `TOKEN=${apiKey}`
            }
        };

        // Ejecutamos el fetch
        const response = await fetch(options.url + '?' + new URLSearchParams(options.params), {
            method: options.method,
            headers: options.headers
        });

        if (!response.ok) {
            throw new Error(`Error en la API de WhoisJSON: status ${response.status}`);
        }

        const data = await response.json();
        
        // ¡OJO ACÁ! Esto imprimirá en tu terminal de Render todo lo que responde la API
        console.log("📦 Datos recibidos de WhoisJSON:", data);

        // ==========================================
        // 3. GENERACIÓN DEL INFORME Y BANDERAS ROJAS
        // ==========================================
        let edadDias = "Desconocida";
        let nivelRiesgo = "DESCONOCIDO";
        let banderasRojas = [];

        // Adaptamos la extracción a los nombres de variables más comunes de WhoisJSON
        // Si al revisar tus logs de Render ves que la fecha viene en otra llave, lo ajustamos aquí
        const fechaCreacion = data.created || data.creation_date || (data.domain && data.domain.created_date);
        const fechaExpiracion = data.expires || data.expiration_date || (data.domain && data.domain.expiration_date);
        const registrador = data.registrar?.name || data.registrar || "Desconocido";

        // Análisis de fechas
        if (fechaCreacion) {
            const creationDate = new Date(fechaCreacion);
            const hoy = new Date();
            edadDias = Math.floor((hoy - creationDate) / (1000 * 60 * 60 * 24));

            // Reglas del motor de seguridad
            if (edadDias < 30) {
                banderasRojas.push("Dominio críticamente nuevo (creado hace menos de 30 días). Altísima probabilidad de Phishing.");
            } else if (edadDias < 180) {
                banderasRojas.push("Dominio relativamente nuevo (menos de 6 meses de antigüedad).");
            }

            if (fechaExpiracion) {
                const expiresDate = new Date(fechaExpiracion);
                const diasParaExpirar = Math.floor((expiresDate - hoy) / (1000 * 60 * 60 * 24));
                if (diasParaExpirar < 30) {
                    banderasRojas.push("El dominio está a punto de expirar en menos de 30 días. Suele indicar sitios temporales.");
                }
            }
        } else {
            banderasRojas.push("No se pudo obtener la fecha de creación del dominio. El registro podría ser irregular.");
        }

        // Determinación final del riesgo
        if (banderasRojas.length >= 2 || edadDias < 30) {
            nivelRiesgo = "ALTO";
        } else if (banderasRojas.length === 1) {
            nivelRiesgo = "MEDIO";
        } else {
            nivelRiesgo = "BAJO";
        }

        // ==========================================
        // 4. RESPONDER AL FRONTEND (EL INFORME)
        // ==========================================
        return res.json({
            success: true,
            reporte_seguridad: {
                objetivo: {
                    url_completa: url,
                    dominio_base: domain
                },
                evaluacion: {
                    nivel_riesgo: nivelRiesgo,
                    es_seguro: nivelRiesgo === "BAJO" || nivelRiesgo === "MEDIO",
                    total_banderas_rojas: banderasRojas.length,
                    advertencias: banderasRojas
                },
                datos_tecnicos: {
                    antiguedad_dias: edadDias,
                    fecha_creacion: fechaCreacion || "Desconocida",
                    fecha_expiracion: fechaExpiracion || "Desconocida",
                    empresa_registradora: registrador
                }
            }
        });

    } catch (error) {
        console.error("Error al generar el informe de seguridad:", error);
        return res.status(500).json({ 
            success: false, 
            message: "Error interno del servidor al consultar la información del dominio." 
        });
    }
}

module.exports = { verifyUrl };