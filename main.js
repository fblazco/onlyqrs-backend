// controllers/scanner.controller.js

async function verifyUrl(req, res) {
    try {
        // 1. Recibimos la URL del frontend
        const { url } = req.body;

        if (!url) {
            return res.status(400).json({ 
                success: false, 
                message: "Debes enviar una URL para analizar." 
            });
        }

        console.log(`🔍 Analizando URL en VirusTotal: ${url}`);

        // ==========================================
        // 2. LA CONSULTA A LA API EXTERNA (VIRUSTOTAL)
        // ==========================================
        
        // VirusTotal requiere que transformemos la URL a formato 'base64url'
        const encodedUrl = Buffer.from(url).toString('base64url');
        
        // Hacemos el fetch real a la API
        const response = await fetch(`https://www.virustotal.com/api/v3/urls/${encodedUrl}`, {
            method: 'GET',
            headers: {
                'x-apikey': '9daa4a1c3a63d2aaaee66917e0dec77a6fa6cf6c922b66a7f03dd6a25b19dbd0'
            }
        });

        // Manejo especial: Si la URL es 100% nueva y nadie nunca la ha analizado en VirusTotal, 
        // la API devuelve un error 404 (Not Found).
        if (response.status === 404) {
            return res.json({
                success: true,
                data: {
                    url_analizada: url,
                    es_seguro: true,
                    mensaje: "URL no registrada en la base de datos de amenazas (Asumida como segura)."
                }
            });
        }

        // Si la API falla por otra cosa (ej: se te acabaron las cuotas gratis)
        if (!response.ok) {
            throw new Error(`Error en VirusTotal: status ${response.status}`);
        }

        // Parseamos el JSON que nos manda VirusTotal
        const externalData = await response.json();
        
        // VirusTotal nos devuelve estadísticas de cuántos antivirus detectaron algo
        const stats = externalData.data.attributes.last_analysis_stats;
        
        // Sumamos los motores que dijeron que era malicioso o sospechoso
        const amenazasEncontradas = stats.malicious + stats.suspicious;
        
        // ==========================================

        // 3. RESPONDER AL FRONTEND
        // Si 0 antivirus detectaron amenazas, es seguro.
        const isSafe = amenazasEncontradas === 0;

        return res.json({
            success: true,
            data: {
                url_analizada: url,
                es_seguro: isSafe,
                mensaje: isSafe 
                    ? "Sitio seguro. Ningún motor de seguridad detectó amenazas." 
                    : `¡Peligro! ${amenazasEncontradas} motores de seguridad detectaron malware o phishing en este sitio.`
            }
        });

    } catch (error) {
        console.error("Error al analizar la URL:", error);
        return res.status(500).json({ 
            success: false, 
            message: "Error interno del servidor al consultar la API externa." 
        });
    }
}

module.exports = { verifyUrl };