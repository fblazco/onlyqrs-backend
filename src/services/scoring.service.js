// src/services/scoring.service.js

function calculateRisk(megaJson) {
    console.log("⚖️ [Scoring] Calculando puntaje total de riesgo...");
    
    let totalScore = 0;
    let combinedFlags = [];

    // ==========================================
    // 1. RECOLECCIÓN DE PUNTAJES POR MOTOR
    // ==========================================

    // A. Motor Heurístico
    if (megaJson.heuristic && !megaJson.heuristic.error) {
        totalScore += megaJson.heuristic.score || 0;
        if (megaJson.heuristic.flags && Array.isArray(megaJson.heuristic.flags)) {
            combinedFlags.push(...megaJson.heuristic.flags);
        }
    }

    // B. Motor Google Safe Browsing
    if (megaJson.googlesb && !megaJson.googlesb.error) {
        if (megaJson.googlesb.detected) {
            totalScore += 35;
            combinedFlags.push({
                code: "google_blacklist",
                severity: "CRITICAL",
                reason: `Google Safe Browsing ha clasificado este enlace como: ${megaJson.googlesb.threatType}`,
                pointsAdded: 35
            });
        }
    }

    // C. Motor URLhaus (Abuse.ch)
    if (megaJson.abuse && !megaJson.abuse.error) {
        if (megaJson.abuse.detected) {
            totalScore += 30;
            combinedFlags.push({
                code: "urlhaus_malware",
                severity: "CRITICAL",
                reason: `URLhaus detectó que este enlace distribuye ${megaJson.abuse.threat}. Estado actual del servidor atacante: ${megaJson.abuse.status}.`,
                pointsAdded: 30
            });
        }
    }

    // D. Motor PhishDestroy
    if (megaJson.phishdestroy && !megaJson.phishdestroy.error) {
        if (megaJson.phishdestroy.detected) {
            totalScore += 15;
            
            const palabrasDetectadas = megaJson.phishdestroy.matched_keywords && megaJson.phishdestroy.matched_keywords.length > 0
                ? megaJson.phishdestroy.matched_keywords.join(', ') 
                : 'Ninguna específica';

            combinedFlags.push({
                code: "phishdestroy_campaign",
                severity: megaJson.phishdestroy.severity ? megaJson.phishdestroy.severity.toUpperCase() : "HIGH",
                reason: `PhishDestroy identificó una amenaza activa. Palabras clave interceptadas: [${palabrasDetectadas}]. Nivel de riesgo de la API: ${megaJson.phishdestroy.risk_score}/100.`,
                pointsAdded: 15
            });
        }
    }

    // E. Motor URLScan.io
    if (megaJson.scanio && !megaJson.scanio.error) {
        if (megaJson.scanio.found && megaJson.scanio.malicious) {
            totalScore += 20;
            combinedFlags.push({
                code: "urlscan_historical_malicious",
                severity: "HIGH",
                reason: "URLScan.io tiene registros previos marcando este dominio o servidor como malicioso/phishing.",
                pointsAdded: 20
            });
        }
    }

    // F. Motor VirusTotal
    // F. Motor VirusTotal (¡Ahora es dinámico!)
    if (megaJson.virustotal && !megaJson.virustotal.error) {
        const { malicious, suspicious } = megaJson.virustotal;
        
        if (malicious > 0) {
            // Le daremos 15 puntos por CADA motor que lo detecte.
            // Si 13 lo detectan (13 * 15) = 195 puntos. Reventará el límite de 100 y será CRITICAL automático.
            const vtPuntaje = malicious * 5; 
            totalScore += vtPuntaje; 
            
            combinedFlags.push({
                code: "virustotal_malicious",
                severity: "CRITICAL",
                reason: `${malicious} motores de antivirus en VirusTotal clasifican esta URL como peligrosa.`,
                pointsAdded: vtPuntaje
            });
        } 
        else if (suspicious > 0) {
            // 5 puntos por cada motor sospechoso
            const vtSusScore = suspicious * 5;
            totalScore += vtSusScore;
            
            combinedFlags.push({
                code: "virustotal_suspicious",
                severity: "MEDIUM",
                reason: `${suspicious} motores en VirusTotal marcaron esta URL como sospechosa.`,
                pointsAdded: vtSusScore
            });
        }
    }

    // G. Motor Whois
    if (megaJson.whois && !megaJson.whois.error && megaJson.whois.found) {
        const edadDias = megaJson.whois.age_in_days;

        if (edadDias < 30) {
            totalScore += 10;
            combinedFlags.push({
                code: "young_domain",
                severity: "HIGH",
                reason: `El dominio fue registrado hace apenas ${edadDias} días. Los sitios legítimos suelen tener años de antigüedad.`,
                pointsAdded: 10
            });
        } else if (edadDias < 90) {
            totalScore += 5;
            combinedFlags.push({
                code: "relatively_new_domain",
                severity: "MEDIUM",
                reason: `El dominio es relativamente nuevo (tiene ${edadDias} días de antigüedad).`,
                pointsAdded: 5
            });
        }
    }

    // ==========================================
    // 2. NORMALIZACIÓN DEL PUNTAJE
    // ==========================================
    totalScore = Math.max(0, Math.min(totalScore, 100));

    // ==========================================
    // 3. MAPEO DEL NIVEL DE RIESGO
    // ==========================================
    let riskLevel = "SAFE";
    
    if (totalScore >= 81) {
        riskLevel = "CRITICAL";
    } else if (totalScore >= 61) {
        riskLevel = "HIGH";
    } else if (totalScore >= 41) {
        riskLevel = "MEDIUM";
    } else if (totalScore >= 21) {
        riskLevel = "LOW";
    }

    // ==========================================
    // 4. RETORNO DEL VEREDICTO
    // ==========================================
    return {
        score: totalScore,
        riskLevel: riskLevel,
        flags: combinedFlags 
    };
}

module.exports = { calculateRisk };