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
        // 2. CONSULTA A LA API DE WHOIS
        // ==========================================
        const apiKey = "de19a8ade5ee6b15af412d6af021fa2431554783d1ce89eb03c25e98a3714d6e";
        const apiUrl = `https://www.whoisxmlapi.com/api/v1?apiKey=${apiKey}&domainName=${domain}&outputFormat=JSON`;

        const response = await fetch(apiUrl);

        if (!response.ok) {
            throw new Error(`Error en la API de Whois: status ${response.status}`);
        }

        const data = await response.json();

        // ==========================================
        // 3. GENERACIÓN DEL INFORME Y BANDERAS ROJAS
        // ==========================================
        const record = data.WhoisRecord || {};
        let edadDias = "Desconocida";
        let nivelRiesgo = "DESCONOCIDO";
        let banderasRojas = [];

        // Extraemos datos extra útiles para el reporte
        const registrador = record.registrarName || "Oculto / Desconocido";
        const paisOrigen = record.registrant?.country || record.registryData?.registrant?.country || "Oculto";
        const organizacion = record.registrant?.organization || record.registryData?.registrant?.organization || "Privacidad Activada";

        // Análisis de fechas
        if (record.createdDate) {
            const creationDate = new Date(record.createdDate);
            const hoy = new Date();
            edadDias = Math.floor((hoy - creationDate) / (1000 * 60 * 60 * 24));

            // Reglas del motor de seguridad
            if (edadDias < 30) {
                banderasRojas.push("Dominio críticamente nuevo (creado hace menos de 30 días). Altísima probabilidad de Phishing.");
            } else if (edadDias < 180) {
                banderasRojas.push("Dominio relativamente nuevo (menos de 6 meses de antigüedad).");
            }

            // Analizar fecha de expiración (los estafadores suelen arrendar dominios por el mínimo de tiempo: 1 año)
            if (record.expiresDate) {
                const expiresDate = new Date(record.expiresDate);
                const diasParaExpirar = Math.floor((expiresDate - hoy) / (1000 * 60 * 60 * 24));
                if (diasParaExpirar < 30) {
                    banderasRojas.push("El dominio está a punto de expirar en menos de 30 días. Suele indicar sitios temporales.");
                }
            }
        } else {
            banderasRojas.push("No se pudo obtener la fecha de creación del dominio. El registro podría ser irregular.");
        }

        // Si los datos del propietario están ocultos (muy común, pero suma sospecha si la página es nueva)
        if (organizacion.includes("Privacidad") || organizacion === "Oculto") {
            banderasRojas.push("El propietario del dominio tiene activada la protección de privacidad WHOIS.");
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
                    fecha_creacion: record.createdDate ? record.createdDate.split('T')[0] : "Desconocida",
                    fecha_expiracion: record.expiresDate ? record.expiresDate.split('T')[0] : "Desconocida",
                    empresa_registradora: registrador,
                    propietario: {
                        organizacion: organizacion,
                        pais: paisOrigen
                    }
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