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

        console.log(`🔍 Generando informe de seguridad (VirusTotal) para: ${url}`);

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

        // 🚨 ==========================================
        // 1.5 MOCK DE PRUEBA (EL LINK ULTRA MALO EXAGERADO)
        // ==========================================
        if (domain === "hacker-page.com" || domain === "www.hacker-page.com") {
            console.log("😈 [ALERTA] Simulacro activado: Devolviendo el peor escenario posible.");
            
            return res.json({
                success: true,
                reporte_seguridad: {
                    objetivo: {
                        url_completa: url,
                        dominio_base: domain
                    },
                    evaluacion: {
                        nivel_riesgo: "CRÍTICO",
                        es_seguro: false,
                        total_banderas_rojas: 7,
                        advertencias: [
                            "🚨 [PELIGRO INMINENTE] Dominio creado hace apenas 15 minutos. Nivel de amenaza máximo.",
                            "🚨 [PHISHING] Se detectó un intento de suplantación de identidad bancaria.",
                            "🚨 [INFRAESTRUCTURA] Servidor alojado en una red conocida internacionalmente por distribuir Ransomware.",
                            "🚨 [PRIVACIDAD] El creador ocultó su identidad utilizando múltiples capas de proxys.",
                            "🚨 [SEGURIDAD] El sitio tiene scripts maliciosos intentando robar cookies de sesión.",
                            "🚨 [RED] Dirección IP asociada a una Botnet actualmente activa.",
                            "🚨 [SOSPECHA] Dominio configurado para autodestruirse y borrar sus rastros en menos de 12 horas."
                        ]
                    },
                    datos_tecnicos: {
                        antiguedad_dias: 0,
                        motores_maliciosos: 65,
                        motores_sospechosos: 5
                    }
                }
            });
        }

        // ==========================================
        // 2. CONSULTA A LA API DE VIRUSTOTAL (v3)
        // ==========================================
        const apiKey = process.env.VIRUSTOTAL_API_KEY;
        
        if (!apiKey) {
            throw new Error("Falta la variable VIRUSTOTAL_API_KEY en Render o .env");
        }

        // VirusTotal v3 requiere que la URL se envíe como un hash Base64 sin signos de igual
        const urlIdBase64 = Buffer.from(url).toString('base64').replace(/=/g, '');

        const options = {
            method: 'GET',
            url: `https://www.virustotal.com/api/v3/urls/${urlIdBase64}`,
            headers: {
                'x-apikey': apiKey
            }
        };

        const response = await fetch(options.url, options);

        // Si VirusTotal devuelve 404, significa que NADIE en el mundo ha escaneado este link antes.
        // Este es el problema de "Día Cero" que discutimos.
        if (response.status === 404) {
            console.log("⚠️ URL no encontrada en la base de datos de VirusTotal.");
            return res.json({
                success: true,
                reporte_seguridad: {
                    objetivo: { url_completa: url, dominio_base: domain },
                    evaluacion: {
                        nivel_riesgo: "MEDIO", // Le damos medio por precaución al ser desconocido
                        es_seguro: true,
                        total_banderas_rojas: 1,
                        advertencias: ["La URL es completamente nueva o nunca ha sido analizada por VirusTotal. Proceder con precaución."]
                    },
                    datos_tecnicos: {
                        antiguedad_dias: "Desconocida",
                        motores_maliciosos: 0,
                        motores_sospechosos: 0
                    }
                }
            });
        }

        if (!response.ok) {
            throw new Error(`Error en la API de VirusTotal: status ${response.status}`);
        }

        const vtData = await response.json();
        console.log("📦 Datos recibidos de VirusTotal:", vtData.data.attributes.last_analysis_stats);

        // ==========================================
        // 3. GENERACIÓN DEL INFORME Y BANDERAS ROJAS
        // ==========================================
        const stats = vtData.data.attributes.last_analysis_stats;
        let nivelRiesgo = "BAJO";
        let banderasRojas = [];

        if (stats.malicious > 0) {
            banderasRojas.push(`🚨 ${stats.malicious} motores de antivirus detectaron este sitio como MALICIOSO.`);
        }
        if (stats.suspicious > 0) {
            banderasRojas.push(`⚠️ ${stats.suspicious} motores marcaron este sitio como SOSPECHOSO.`);
        }

        // Determinación del riesgo basado en los votos de los antivirus
        if (stats.malicious >= 2) {
            nivelRiesgo = "ALTO";
        } else if (stats.malicious === 1 || stats.suspicious >= 2) {
            nivelRiesgo = "MEDIO";
        } else if (banderasRojas.length === 0) {
            nivelRiesgo = "BAJO";
        }

        // ==========================================
        // 4. RESPONDER AL FRONTEND
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
                    es_seguro: nivelRiesgo === "BAJO",
                    total_banderas_rojas: banderasRojas.length,
                    advertencias: banderasRojas
                },
                datos_tecnicos: {
                    antiguedad_dias: "No aplicable en VirusTotal",
                    motores_maliciosos: stats.malicious,
                    motores_sospechosos: stats.suspicious,
                    motores_inofensivos: stats.harmless
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