// src/services/strategies/ThreatStrategy.js

class ThreatStrategy {
    /**
     * Método principal que todas las estrategias hijas (GoogleSB, Whois, etc.) 
     * deben implementar obligatoriamente.
     * * @param {string} urlToAnalyze - La URL que el usuario escaneó en el QR.
     * @returns {Promise<Object>} - El resultado del análisis de este motor específico.
     */
    async analyze(urlToAnalyze) {
        // this.constructor.name imprimirá el nombre de la clase hija (ej: "VirusTotalStrategy")
        throw new Error(`🛑 Error de Arquitectura: El motor [${this.constructor.name}] no ha implementado su método analyze().`);
    }
}

module.exports = ThreatStrategy;