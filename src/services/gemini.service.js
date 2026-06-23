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
        const razones = flags.map(flag => `- ${flag.reason}`).join('\n');

        const prompt = `
            Eres un experto en ciberseguridad trabajando en el backend de la aplicación OnlyQRs.
            Tu trabajo es explicarle a un usuario común (sin conocimientos técnicos) por qué un código QR es peligroso o seguro.
            
            REGLAS ESTRICTAS:
            1. NO debes calcular ni decidir el riesgo. El motor matemático ya lo hizo.
            2. Tu respuesta debe tener un MÁXIMO DE 5 LÍNEAS. Sé directo y claro.
            3. No uses lenguaje extremadamente técnico (evita hablar de "heurística", "APIs" o "TLDs").
            4. Si el nivel de riesgo es HIGH o CRITICAL, advierte explícitamente que no abran el enlace ni ingresen datos.

            DATOS DEL ANÁLISIS:
            - Nivel de Riesgo Calculado: ${riskLevel}
            - Puntaje de Peligro: ${score}/100
            - Indicadores encontrados:
            ${razones || "Ningún indicador de riesgo detectado."}

            Redacta la explicación para el usuario ahora:
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
        case 'HIGH':
            return "Peligro: Este código QR dirige a un sitio con múltiples indicadores de fraude o malware. Se recomienda encarecidamente no abrir el enlace ni ingresar información personal.";
        case 'MEDIUM':
            return "Precaución: El enlace presenta algunas características sospechosas. Proceda con cuidado y verifique que la página sea oficial antes de ingresar datos.";
        default:
            return "Seguro: El enlace no ha levantado alertas de seguridad en nuestros motores de análisis. Parece seguro de visitar.";
    }
}

module.exports = { generateSummary };