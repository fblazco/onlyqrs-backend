// src/services/strategies/HeuristicStrategy.js
const ThreatStrategy = require('./ThreatStrategy');
const net = require('net'); // Módulo nativo de Node.js para redes

class HeuristicStrategy extends ThreatStrategy {
    async analyze(urlToAnalyze) {
        console.log(`🧠 [Heuristic] Ejecutando análisis local enriquecido para: ${urlToAnalyze}`);
        
        let score = 0;
        let flags = [];

        // Función auxiliar para agregar banderas ordenadas y estandarizadas
        const addFlag = (code, severity, reason, pointsAdded) => {
            score += pointsAdded;
            flags.push({ code, severity, reason, pointsAdded });
        };
        
        try {
            // 1. Detección de URLs excesivamente largas (Antes de parsear)
            if (urlToAnalyze.length > 75) {
                addFlag(
                    "long_url", 
                    "LOW", 
                    "La URL es inusualmente larga, una técnica común para ocultar el destino final del enlace.", 
                    10
                );
            }

            const parsedUrl = new URL(urlToAnalyze);
            const domain = parsedUrl.hostname.toLowerCase();
            const fullUrlPath = (parsedUrl.hostname + parsedUrl.pathname + parsedUrl.search).toLowerCase();

            // 2. Detección de IP en lugar de dominio
            if (net.isIP(domain)) {
                addFlag(
                    "ip_based_url", 
                    "HIGH", 
                    "El enlace utiliza una dirección IP directa en lugar de un dominio registrado.", 
                    30
                );
            }

            // 3. Uso del carácter @ (Credenciales ofuscadas)
            if (parsedUrl.username || parsedUrl.password || urlToAnalyze.includes('@')) {
                addFlag(
                    "contains_at_symbol", 
                    "HIGH", 
                    "Utiliza el símbolo '@' en la URL, un método frecuente para esconder el dominio real.", 
                    25
                );
            }

            // 4. Puertos no estándar
            if (parsedUrl.port && !['80', '443', '8080'].includes(parsedUrl.port)) {
                addFlag(
                    "non_standard_port", 
                    "MEDIUM", 
                    `Conecta a través del puerto inusual ${parsedUrl.port}.`, 
                    15
                );
            }

            // 5. Exceso de guiones en el dominio
            const hyphensCount = (domain.match(/-/g) || []).length;
            if (hyphensCount >= 3) {
                addFlag(
                    "excessive_hyphens", 
                    "MEDIUM", 
                    `El dominio contiene ${hyphensCount} guiones, un patrón recurrente en sitios fraudulentos.`, 
                    15
                );
            }

            // 6. Doble extensión sospechosa
            const doubleExtRegex = /\.[a-z0-9]{2,4}\.(exe|js|scr|bat|cmd|vbs|sh|ps1)$/i;
            if (doubleExtRegex.test(parsedUrl.pathname)) {
                addFlag(
                    "suspicious_double_extension", 
                    "CRITICAL", 
                    "El enlace apunta a un archivo con doble extensión ejecutable (ej: documento.pdf.exe).", 
                    40
                );
            }

            // 7. Servicios acortadores
            const shorteners = ['bit.ly', 't.co', 'tinyurl.com', 'ow.ly', 'goo.gl', 'is.gd', 'buff.ly', 'adf.ly', 'cutt.ly'];
            if (shorteners.includes(domain)) {
                addFlag(
                    "url_shortener", 
                    "MEDIUM", 
                    "Utiliza un servicio para acortar URLs, lo que impide ver la página de destino real.", 
                    20
                );
            }

            // 8. Detección de Brand Spoofing (Marcas conocidas)
            const marcasOficiales = ['paypal', 'google', 'amazon', 'microsoft', 'bancoestado', 'santander', 'bci', 'netflix', 'apple', 'facebook'];
            for (const marca of marcasOficiales) {
                if (domain.includes(marca)) {
                    // Validamos si la marca está siendo usada de forma ilegítima (ej: soporte-bancoestado.xyz)
                    const isOficial = domain === `${marca}.com` || domain === `${marca}.cl` || domain.endsWith(`.${marca}.com`) || domain.endsWith(`.${marca}.cl`);
                    if (!isOficial) {
                        addFlag(
                            "brand_spoofing", 
                            "CRITICAL", 
                            `Intenta suplantar la marca "${marca}" utilizando un dominio no oficial.`, 
                            40
                        );
                        break; // Cortamos para no sumar más puntos por otras marcas
                    }
                }
            }

            // 9. Detección de Subdominios Excesivos (De tu lógica original)
            const partesDominio = domain.split('.');
            if (!net.isIP(domain) && partesDominio.length > 3) {
                addFlag(
                    "many_subdomains", 
                    "MEDIUM", 
                    "Posee demasiados subdominios, táctica usada para evadir filtros de seguridad.", 
                    15
                );
            }

            // 10. TLDs Sospechosos (De tu lógica original)
            const tldsPeligrosos = ['.xyz', '.top', '.click', '.loan', '.zip', '.mov', '.tk', '.ml'];
            if (tldsPeligrosos.some(tld => domain.endsWith(tld))) {
                addFlag(
                    "suspicious_tld", 
                    "HIGH", 
                    "Usa una extensión de dominio económica comúnmente asociada a campañas de malware.", 
                    20
                );
            }

            // 11. Palabras clave de Phishing (De tu lógica original)
            const palabrasPeligrosas = ['login', 'verify', 'secure', 'update', 'account', 'bank', 'payment', 'wallet', 'signin'];
            const keywordsFound = palabrasPeligrosas.filter(palabra => fullUrlPath.includes(palabra));
            
            if (keywordsFound.length > 0) {
                addFlag(
                    "suspicious_keyword", 
                    keywordsFound.length >= 2 ? "HIGH" : "MEDIUM", 
                    `Contiene términos gancho: ${keywordsFound.join(', ')}.`, 
                    keywordsFound.length * 10 // +10 pts por cada palabra
                );
            }

            // ==========================================
            // NORMALIZACIÓN FINAL
            // ==========================================
            score = Math.min(score, 100);

            return { score, flags };

        } catch (error) {
            console.error("❌ [Heuristic] Error al analizar formato de URL:", error.message);
            // Si estalla el new URL(), la string es tan mala que merece riesgo crítico
            return { 
                score: 100, 
                flags: [{
                    code: "invalid_url_format",
                    severity: "CRITICAL",
                    reason: "El formato de la URL es completamente inválido o malicioso.",
                    pointsAdded: 100
                }] 
            };
        }
    }
}

module.exports = HeuristicStrategy;