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

        console.log(`🔍 Analizando URL: ${url}`);

        // ==========================================
        // 2. LA CONSULTA A LA API EXTERNA
        // ==========================================
        // Aquí es donde harás la llamada a la API real. 
        // Por ahora, pondremos una simulación didáctica para que veas cómo se arma.
        
        /* EJEMPLO DE CÓMO SERÁ EL CÓDIGO REAL:
        const response = await fetch(`https://api.de-seguridad.com/check?url=${url}`, {
            headers: { 'Authorization': 'Bearer TU_API_KEY' }
        });
        const externalData = await response.json();
        */

        // SIMULACIÓN (Borraremos esto cuando conectes tu API real)
        // Vamos a simular que la API demora 1 segundo en responder
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        // Simulamos que cualquier link que tenga la palabra "hack" o "virus" es malicioso
        const isMalicious = url.includes("hack") || url.includes("virus");
        
        const simulatedExternalData = {
            risk_level: isMalicious ? "HIGH" : "LOW",
            details: isMalicious ? "Phishing detectado" : "Sitio seguro"
        };
        // ==========================================


        // 3. RESPONDER AL FRONTEND
        // Traducimos lo que sea que nos dijo la API externa a nuestro propio formato estándar
        const isSafe = simulatedExternalData.risk_level === "LOW";

        return res.json({
            success: true,
            data: {
                url_analizada: url,
                es_seguro: isSafe,
                mensaje: simulatedExternalData.details
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