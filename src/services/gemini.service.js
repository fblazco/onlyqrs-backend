// src/services/gemini.service.js
const { GoogleGenerativeAI } = require("@google/generative-ai");

// Inicializamos el SDK con la llave de entorno
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

/**
 * Genera un resumen explicativo del riesgo usando Gemini 1.5 Flash.
 * @param {number} score - Puntaje del 0 al 100.
 * @param {string} riskLevel - Nivel de riesgo (SAFE, LOW, MEDIUM, HIGH, CRITICAL).
 * @param {Array} flags - Arreglo de objetos enriquecidos con las razones de los motores.
 * @returns {Promise<string>} - El resumen en texto plano (máximo 3 líneas).
 */
async function generateSummary(score, riskLevel, flags) {
    console.log(`🤖 [Gemini] Redactando resumen para riesgo ${riskLevel} (${score}/100)...`);

    if (!process.env.GEMINI_API_KEY) {
        console.warn("⚠️ [Gemini] Falta GEMINI_API_KEY. Retornando resumen genérico.");
        return fallbackSummary(riskLevel);
    }

    try {
        // Usamos Flash porque es rapidísimo y perfecto para tareas de texto cortas
        const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash" });        // Extraemos solo las "razones" de los flags para pasárselas a la IA
        const razones = flags
            .map(flag =>
                `- [${flag.severity}] ${flag.code}: ${flag.reason}`
            )
            .join('\n');
        const prompt = `
        Eres un analista de ciberseguridad del sistema OnlyQRs.

        Tu tarea es redactar un informe breve basado en el resultado de un análisis automatizado de una URL obtenida desde un código QR.

        REGLAS:

        1. NO recalcules ni modifiques el nivel de riesgo. El score ya fue calculado por el motor de análisis.
        2. Explica de forma clara qué indicadores fueron encontrados.
        3. Puedes utilizar términos técnicos simples como:
        - phishing
        - malware
        - dominio sospechoso
        - suplantación de identidad
        - URL acortada
        - subdominios
        - dirección IP
        4. Relaciona los hallazgos con el posible riesgo para el usuario.
        5. Finaliza siempre con una recomendación de seguridad.
        6. La respuesta debe tener entre 4 y 8 líneas.
        7. No inventes información que no aparezca en los indicadores.
        8. Escribe en español neutro.

        DATOS DEL ANÁLISIS

        Nivel de Riesgo: ${riskLevel}

        Score: ${score}/100

        Indicadores detectados:

        ${razones || "No se detectaron indicadores relevantes."}

        Redacta un informe breve explicando:
        - Qué se detectó.
        - Por qué podría representar un riesgo.
        - Qué debería hacer el usuario.
        `;

        const result = await model.generateContent(prompt);
        const responseText = result.response.text().trim();

        return responseText;

    } catch (error) {
        console.error("❌ [Gemini] Error al generar el resumen:", error.message);
        // Si la API de Google falla (por cuota o caída), no botamos el escáner,
        // devolvemos un texto seguro por defecto para que el frontend del Grupo 5 no se rompa.
        return fallbackSummary(riskLevel);
    }
}

/**
 * Función de respaldo en caso de que la API de Gemini falle o no haya Key.
 */
function fallbackSummary(riskLevel) {

    switch (riskLevel) {

        case 'CRITICAL':
            return `
Se detectaron múltiples indicadores asociados a phishing, fraude o distribución de malware.
El análisis encontró comportamientos típicos observados en campañas maliciosas.
Existe una alta probabilidad de que el enlace busque robar información o redirigir a contenido peligroso.
Recomendación: no abrir la URL ni ingresar datos personales, bancarios o credenciales.
            `.trim();

        case 'HIGH':
            return `
La URL presenta varios indicadores de riesgo relevantes y características compatibles con sitios fraudulentos.
Algunos elementos observados son comunes en campañas de phishing y suplantación de identidad.
Aunque no se puede confirmar una amenaza activa, el riesgo es elevado.
Recomendación: evitar acceder al enlace y verificar la fuente original.
            `.trim();

        case 'MEDIUM':
            return `
Se identificaron algunos patrones sospechosos durante el análisis.
No existen evidencias concluyentes de actividad maliciosa, pero se detectaron características que ameritan precaución.
La legitimidad del sitio no puede garantizarse completamente.
Recomendación: verificar cuidadosamente el dominio antes de interactuar con él.
            `.trim();

        case 'LOW':
            return `
El análisis detectó pocos indicadores de riesgo y no se encontraron señales significativas de actividad maliciosa.
Los motores de inteligencia consultados no reportaron amenazas importantes.
Aun así, ningún sistema puede garantizar seguridad absoluta.
Recomendación: mantener buenas prácticas de navegación y verificar siempre la procedencia del QR.
            `.trim();

        case 'SAFE':
        default:
            return `
No se detectaron indicadores relevantes de phishing, malware o fraude.
Las fuentes consultadas no reportan actividad sospechosa asociada al enlace.
La URL parece legítima según la información disponible.
Recomendación: navegar con normalidad manteniendo las precauciones habituales de seguridad.
            `.trim();
    }
}

module.exports = { generateSummary };