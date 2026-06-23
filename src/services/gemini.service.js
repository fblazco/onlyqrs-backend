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
/**
 * Procesa el historial de escaneos, calcula estadísticas descriptivas en Node.js
 * y solicita a Gemini una interpretación experta en formato JSON estructurado.
 * * @param {Array} historyRecords - Filas completas obtenidas de la base de datos (Sequelize).
 * @returns {Promise<Object>} Estructura final lista para el dashboard de React.
 */
async function generateHistoryAnalytics(historyRecords) {
    console.log(`🤖 [Gemini Analytics] Procesando ${historyRecords.length} registros en el backend...`);

    if (!process.env.GEMINI_API_KEY) {
        throw new Error("Falta la variable GEMINI_API_KEY en las variables de entorno.");
    }

    // =================================================================
    // PASO 1: CÁLCULO DE ESTADÍSTICAS E INDICADORES EN NODE.JS (Cero Alucinaciones)
    // =================================================================
    const statistics = {
        totalScans: historyRecords.length,
        safeCount: 0,
        lowCount: 0,
        mediumCount: 0,
        highCount: 0,
        criticalCount: 0
    };

    // Extraemos datos cualitativos limpios para que la IA busque patrones semánticos
    const suspiciousUrlsSample = [];

    historyRecords.forEach(record => {
        const level = (record.riskLevel || 'SAFE').toUpperCase();
        
        // Clasificación exacta basada en la data real de Postgres
        if (level === 'SAFE') statistics.safeCount++;
        else if (level === 'LOW') statistics.lowCount++;
        else if (level === 'MEDIUM') statistics.mediumCount++;
        else if (level === 'HIGH') statistics.highCount++;
        else if (level === 'CRITICAL') statistics.criticalCount++;

        // Alimentamos a la IA solo con enlaces sospechosos para optimizar tokens
        if (['MEDIUM', 'HIGH', 'CRITICAL'].includes(level) && suspiciousUrlsSample.length < 30) {
            suspiciousUrlsSample.push({
                url: record.url,
                risk: level,
                score: record.score
            });
        }
    });

    // =================================================================
    // PASO 2: LLAMADA ESTRUCTURADA A GEMINI
    // =================================================================
    try {
        // Configuramos el modelo para obligarlo a responder EXCLUSIVAMENTE JSON
        const model = genAI.getGenerativeModel({ 
            model: "gemini-2.5-flash",
            generationConfig: {
                responseMimeType: "application/json"
            }
        });

        const prompt = `
            Eres el Analista Principal de Ciberseguridad (CISO) de la plataforma OnlyQRs.
            Tu tarea es interpretar los datos de tráfico recopilados por nuestro backend y redactar conclusiones analíticas muy directas para un dashboard de administración.

            REGLAS DE OPERACIÓN:
            1. NO calcules porcentajes ni inventes números. Confía ciegamente en las estadísticas que ya calculó el servidor.
            2. Tu respuesta debe ser estrictamente un objeto JSON válido que coincida exactamente con la estructura solicitada.
            3. No incluyas explicaciones de texto fuera del JSON, ni bloques de código markdown como \`\`\`json.
            4. Sé conciso y profesional en los textos; cada campo debe contener un párrafo corto explicativo (máximo 3 líneas).

            MÉTRICAS DEL SERVIDOR:
            - Escaneos Totales: ${statistics.totalScans}
            - Distribución de Riesgo: Safe=${statistics.safeCount}, Low=${statistics.lowCount}, Medium=${statistics.mediumCount}, High=${statistics.highCount}, Critical=${statistics.criticalCount}

            MUESTRA DE ENLACES SOSPECHOSOS DETECTADOS:
            ${JSON.stringify(suspiciousUrlsSample)}

            ESTRUCTURA JSON REQUERIDA (Llena los valores con tu análisis basado en los datos provistos):
            {
                "overview": "Resumen ejecutivo del estado de seguridad actual de los códigos QR escaneados esta semana.",
                "topThreat": "Identificación de la amenaza principal o marcas más suplantadas (ej. bancos, correos) detectadas al mirar las palabras clave de la muestra.",
                "infrastructure": "Análisis de las extensiones de dominio (TLDs como .xyz, .top) o patrones estructurales sospechosos observados en la muestra de URLs.",
                "recommendation": "Acción mitigatoria o aviso preventivo directo para proteger a la comunidad de usuarios esta semana."
            }
        `;

        const result = await model.generateContent(prompt);
        const responseText = result.response.text().trim();

        // =================================================================
        // PASO 3: VALIDACIÓN Y PARSEO SEGURO DEL RESULTADO
        // =================================================================
        let executiveReport;
        try {
            executiveReport = JSON.parse(responseText);
        } catch (parseError) {
            console.error("⚠️ [Gemini] La IA no devolvió un JSON perfectamente limpio. Aplicando fallback de emergencia.", parseError.message);
            // Si la IA comete un error de sintaxis, el backend no se rompe y el frontend recibe textos legibles
            executiveReport = generateFallbackReport(statistics);
        }

        // Retornamos el objeto unificado ideal para los componentes de React
        return {
            statistics,
            executiveReport
        };

    } catch (error) {
        console.error("❌ [Gemini Analytics] Error crítico en la comunicación con el proveedor de IA:", error.message);
        // Fallback completo si la API de Google está caída o sufre timeout
        return {
            statistics,
            executiveReport: generateFallbackReport(statistics)
        };
    }
}

/**
 * Genera una interpretación de respaldo basada en reglas estáticas si la IA falla.
 */
function generateFallbackReport(stats) {
    const totalIncidentes = stats.mediumCount + stats.highCount + stats.criticalCount;
    
    if (totalIncidentes > 0) {
        return {
            overview: `Análisis histórico completado. Se registra actividad anómala en el servidor con un total de ${totalIncidentes} alertas activas que requieren supervisión inmediata.`,
            topThreat: "Múltiples vectores interceptados en motores paralelos. Se recomienda inspección manual mediante el panel de auditoría.",
            infrastructure: "Detección de subdominios extensos e inconsistencias estructurales en las campañas almacenadas.",
            recommendation: "Elevar los niveles de alerta en las aplicaciones móviles clientes y aconsejar a los usuarios verificar identidades corporativas."
        };
    }
    
    return {
        overview: "Tráfico histórico analizado de manera satisfactoria. Los niveles globales de amenaza se mantienen dentro de los umbrales seguros.",
        topThreat: "No se identifican campañas de suplantación dirigidas ni vectores de distribución de malware activos en los registros analizados.",
        infrastructure: "Los dominios registrados corresponden en su mayoría a infraestructuras estables y de alta reputación.",
        recommendation: "Continuar con el monitoreo heurístico en tiempo real habitual y mantener actualizadas las firmas de las listas negras."
    };
}
// Recuerda actualizar los exports al final del archivo para incluir la nueva función:
module.exports = { 
    generateSummary, 
    generateHistoryAnalytics,
    generateFallbackReport,
};
