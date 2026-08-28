"""
AI Security Scanner LATAM - Motor de Escaneo
Escanea aplicaciones AI en busca de vulnerabilidades
Versión 100% en español para Latinoamérica
"""

import re
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum


class SeverityLevel(Enum):
    INFO = "info"
    BAJO = "bajo"
    MEDIO = "medio"
    ALTO = "alto"
    CRITICO = "critico"


class VulnCategory(Enum):
    PROMPT_INJECTION = "prompt_injection"
    DATA_LEAKAGE = "data_leakage"
    BIAS = "bias"
    UNSAFE_CONTENT = "unsafe_content"
    OVERRELIANCE = "overreliance"
    MODEL_ABUSE = "model_abuse"
    PRIVACY = "privacy"
    COMPLIANCE = "compliance"


@dataclass
class Vulnerability:
    id: str
    title: str
    description: str
    severity: SeverityLevel
    category: VulnCategory
    evidence: str
    recommendation: str
    cvss_score: float
    references: List[str]


@dataclass
class ScanResult:
    target: str
    vulnerabilities: List[Vulnerability]
    score: float  # 0-100 (100=seguro)
    risk_level: str
    total_vulns: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    summary: str
    recommendations: List[str]


class AISecurityScanner:
    """Escáner de seguridad para aplicaciones AI en español"""
    
    # Patrones de vulnerabilidades
    VULN_PATTERNS = {
        "prompt_injection": {
            "patterns": [
                r"ignore\s+(all\s+)?previous\s+instructions",
                r"disregard\s+(all\s+)?prior",
                r"you\s+are\s+now\s+",
                r"system\s*:\s*you\s+are",
                r"act\s+as\s+if\s+you\s+have\s+no",
            ],
            "severity": SeverityLevel.CRITICO,
            "title": "Vulnerabilidad de Prompt Injection",
            "description": "El sistema AI es vulnerable a ataques de inyección de prompts",
            "recommendation": "Implementar validación de entrada y filtros de seguridad",
        },
        "data_leakage": {
            "patterns": [
                r"show\s+me\s+(your|the)\s+(system\s+)?prompt",
                r"what\s+(is|are)\s+your\s+(instructions?|rules?)",
                r"reveal\s+(your|the)\s+(system|initial)",
                r"output\s+(your|the)\s+(full|complete)",
                r"repeat\s+(everything|all|the)\s+(above|before)",
            ],
            "severity": SeverityLevel.ALTO,
            "title": "Filtración de Datos Sensibles",
            "description": "El sistema puede filtrar información interna",
            "recommendation": "Implementar control de acceso y cifrado de datos sensibles",
        },
        "bias": {
            "patterns": [
                r"(all|every)\s+(men|women|people\s+of)",
                r"(always|never)\s+(men|women|they)",
                r"(typical|stereotypical)\s+(man|woman|black|white)",
                r"(inferior|superior)\s+(race|gender|ethnic)",
            ],
            "severity": SeverityLevel.ALTO,
            "title": "Sesgo Algorítmico Detectado",
            "description": "El modelo puede generar contenido sesgado",
            "recommendation": "Auditar datos de entrenamiento y implementar fairness checks",
        },
        "unsafe_content": {
            "patterns": [
                r"(how\s+to\s+make|instructions?\s+for)\s+(bomb|weapon|drug)",
                r"(bypass|override)\s+(security|safety|restriction)",
                r"(harmful|dangerous|illegal)\s+(content|information)",
                r"(violence|kill|murder|attack)",
            ],
            "severity": SeverityLevel.CRITICO,
            "title": "Contenido Inseguro Permitido",
            "description": "El sistema puede generar contenido peligroso",
            "recommendation": "Implementar filtros de contenido y límites estrictos",
        },
        "overreliance": {
            "patterns": [
                r"(guaranteed|100%\s+accurate|never\s+wrong)",
                r"(always\s+correct|perfect|flawless)",
                r"(definitely|certainly|absolutely)\s+(true|correct)",
                r"(no\s+need\s+to\s+verify|trust\s+me)",
            ],
            "severity": SeverityLevel.MEDIO,
            "title": "Sobre-confianza en el Sistema",
            "description": "El sistema puede generar falsa confianza",
            "recommendation": "Agregar advertencias y fomentar verificación humana",
        },
        "model_abuse": {
            "patterns": [
                r"(create|generate|write)\s+(malware|virus|exploit)",
                r"(phishing|scam|fraud)\s+(email|message|template)",
                r"(fake|forged)\s+(document|id|certificate)",
                r"(impersonate|pretend\s+to\s+be)\s+(someone|authority)",
            ],
            "severity": SeverityLevel.CRITICO,
            "title": "Posible Abuso del Modelo",
            "description": "El sistema puede ser usado para actividades maliciosas",
            "recommendation": "Implementar monitoreo y registro de uso sospechoso",
        },
        "privacy": {
            "patterns": [
                r"(personal|private)\s+(data|information|details)",
                r"(social\s+security|credit\s+card|password)",
                r"(location|address|phone\s+number)",
                r"(medical|health|financial)\s+(record|data)",
            ],
            "severity": SeverityLevel.ALTO,
            "title": "Riesgo de Privacidad",
            "description": "El sistema puede exponer datos personales",
            "recommendation": "Implementar anonimización y minimización de datos",
        },
    }
    
    # Checklist de seguridad AI
    SECURITY_CHECKLIST = {
        "entrada": [
            "Validación de entrada implementada",
            "Límites de longitud configurados",
            "Caracteres especiales filtrados",
            "Rate limiting activo",
        ],
        "modelo": [
            "Modelo actualizado",
            "Fine-tuning revisado",
            "Bias testing completado",
            "Red teaming realizado",
        ],
        "salida": [
            "Filtros de salida activos",
            "PII detection habilitado",
            "Content moderation activo",
            "Logging implementado",
        ],
        "infraestructura": [
            "Cifrado en tránsito (TLS)",
            "Cifrado en reposo",
            "Acceso controlado (RBAC)",
            "Monitoreo de seguridad",
        ],
        "cumplimiento": [
            "GDPR compliance verificado",
            "Política de privacidad publicada",
            "Consentimiento documentado",
            "Derechos del usuario implementados",
        ],
    }
    
    def __init__(self):
        self.compiled_patterns = {}
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Pre-compila patrones"""
        for category, data in self.VULN_PATTERNS.items():
            self.compiled_patterns[category] = [
                re.compile(p, re.IGNORECASE) for p in data["patterns"]
            ]
    
    def scan_text(self, text: str) -> ScanResult:
        """Escanea un texto en busca de vulnerabilidades"""
        vulns = []
        
        for category, data in self.VULN_PATTERNS.items():
            patterns = self.compiled_patterns[category]
            for pattern in patterns:
                matches = pattern.findall(text)
                if matches:
                    vuln = Vulnerability(
                        id=f"AI-{category.upper()}-{len(vulns)+1:03d}",
                        title=data["title"],
                        description=data["description"],
                        severity=data["severity"],
                        category=VulnCategory(category),
                        evidence=f"Patrón detectado: {pattern.pattern}",
                        recommendation=data["recommendation"],
                        cvss_score=self._get_cvss(data["severity"]),
                        references=self._get_references(category)
                    )
                    vulns.append(vuln)
                    break  # Una vulnerabilidad por categoría
        
        return self._generate_result("texto-analizado", vulns)
    
    def scan_code(self, code: str) -> ScanResult:
        """Escanea código fuente en busca de vulnerabilidades AI"""
        vulns = []
        
        # Detectar patrones inseguros en código
        code_patterns = {
            "api_key_exposure": r"(api[_-]?key|secret[_-]?key|password)\s*[=:]\s*['\"][^'\"]+['\"]",
            "hardcoded_credentials": r"(user|pass|login)\s*[=:]\s*['\"][^'\"]+['\"]",
            "unsafe_eval": r"eval\s*\(",
            "sql_injection": r"(query|execute)\s*\([^)]*\+",
            "no_input_validation": r"input\s*\(",
            "verbose_errors": r"(print|console\.log|echo)\s*\(.*error",
        }
        
        for vuln_name, pattern in code_patterns.items():
            if re.search(pattern, code, re.IGNORECASE):
                vulns.append(Vulnerability(
                    id=f"CODE-{vuln_name.upper()[:3]}",
                    title=f"Vulnerabilidad en código: {vuln_name}",
                    description=f"Se detectó patrón inseguro: {vuln_name}",
                    severity=SeverityLevel.MEDIO,
                    category=VulnCategory.MODEL_ABUSE,
                    evidence=f"Patrón: {pattern}",
                    recommendation="Revisar y corregir el código",
                    cvss_score=5.0,
                    references=[]
                ))
        
        return self._generate_result("codigo-analizado", vulns)
    
    def run_checklist(self, config: Dict) -> Dict:
        """Ejecuta checklist de seguridad"""
        results = {}
        
        for area, checks in self.SECURITY_CHECKLIST.items():
            area_results = []
            for check in checks:
                # Verificar si la configuración indica que está implementado
                key = check.lower().replace(" ", "_").replace("(", "").replace(")", "")
                implemented = config.get(key, False)
                area_results.append({
                    "check": check,
                    "implemented": implemented,
                    "status": "✅" if implemented else "❌"
                })
            results[area] = area_results
        
        return results
    
    def _generate_result(self, target: str, vulns: List[Vulnerability]) -> ScanResult:
        """Genera resultado del escaneo"""
        critical = sum(1 for v in vulns if v.severity == SeverityLevel.CRITICO)
        high = sum(1 for v in vulns if v.severity == SeverityLevel.ALTO)
        medium = sum(1 for v in vulns if v.severity == SeverityLevel.MEDIO)
        low = sum(1 for v in vulns if v.severity == SeverityLevel.BAJO)
        
        # Calcular score (100 = seguro, 0 = vulnerable)
        score = 100
        score -= critical * 25
        score -= high * 15
        score -= medium * 8
        score -= low * 3
        score = max(0, score)
        
        # Determinar nivel de riesgo
        if score >= 80:
            risk_level = "BAJO"
        elif score >= 60:
            risk_level = "MEDIO"
        elif score >= 40:
            risk_level = "ALTO"
        else:
            risk_level = "CRÍTICO"
        
        # Generar resumen
        summary = self._generate_summary(score, risk_level, len(vulns), critical, high)
        
        # Generar recomendaciones
        recommendations = self._generate_recommendations(vulns)
        
        return ScanResult(
            target=target,
            vulnerabilities=vulns,
            score=score,
            risk_level=risk_level,
            total_vulns=len(vulns),
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            summary=summary,
            recommendations=recommendations
        )
    
    def _get_cvss(self, severity: SeverityLevel) -> float:
        """Retorna score CVSS estimado"""
        cvss_map = {
            SeverityLevel.CRITICO: 9.0,
            SeverityLevel.ALTO: 7.5,
            SeverityLevel.MEDIO: 5.0,
            SeverityLevel.BAJO: 2.5,
            SeverityLevel.INFO: 0.0,
        }
        return cvss_map.get(severity, 0.0)
    
    def _get_references(self, category: str) -> List[str]:
        """Retorna referencias OWASP/MAISP"""
        refs = {
            "prompt_injection": [
                "OWASP Top 10 for LLMs - LLM01",
                "MITRE ATLAS - Prompt Injection"
            ],
            "data_leakage": [
                "OWASP Top 10 for LLMs - LLM06",
                "GDPR Article 5"
            ],
            "bias": [
                "OWASP Top 10 for LLMs - LLM04",
                "EU AI Act - Article 10"
            ],
            "unsafe_content": [
                "OWASP Top 10 for LLMs - LLM05",
                "Content Safety Guidelines"
            ],
        }
        return refs.get(category, [])
    
    def _generate_summary(self, score: float, risk_level: str, 
                          total: int, critical: int, high: int) -> str:
        """Genera resumen en español"""
        if critical > 0:
            return f"🚨 CRÍTICO: Se encontraron {critical} vulnerabilidades críticas. Se requiere acción inmediata."
        elif high > 0:
            return f"🔴 ALTO RIESGO: {high} vulnerabilidades de alto riesgo detectadas."
        elif total > 0:
            return f"⚠️ RIESGO MEDIO: {total} vulnerabilidades detectadas."
        else:
            return f"✅ SEGURO: No se encontraron vulnerabilidades significativas."
    
    def _generate_recommendations(self, vulns: List[Vulnerability]) -> List[str]:
        """Genera recomendaciones específicas"""
        recs = []
        
        categories = set(v.category for v in vulns)
        
        if VulnCategory.PROMPT_INJECTION in categories:
            recs.append("Implementar validación de entrada y filtros anti-injection")
        if VulnCategory.DATA_LEAKAGE in categories:
            recs.append("Implementar DLP (Data Loss Prevention) y cifrado de datos sensibles")
        if VulnCategory.BIAS in categories:
            recs.append("Realizar auditoría de sesgos y balanced datasets")
        if VulnCategory.UNSAFE_CONTENT in categories:
            recs.append("Agregar filtros de contenido y human-in-the-loop")
        if VulnCategory.OVERRELIANCE in categories:
            recs.append("Incluir advertencias sobre limitaciones del modelo")
        if VulnCategory.MODEL_ABUSE in categories:
            recs.append("Implementar monitoreo de uso y rate limiting")
        if VulnCategory.PRIVACY in categories:
            recs.append("Implementar anonimización y cumplimiento GDPR/LFPDPPP")
        
        if not recs:
            recs.append("Mantener práctica de seguridad AI actualizada")
        
        return recs
    
    def get_stats(self) -> Dict:
        """Retorna estadísticas del scanner"""
        return {
            "vulnerability_categories": len(self.VULN_PATTERNS),
            "total_patterns": sum(len(v["patterns"]) for v in self.VULN_PATTERNS.values()),
            "checklist_areas": len(self.SECURITY_CHECKLIST),
            "total_checks": sum(len(v) for v in self.SECURITY_CHECKLIST.values()),
            "version": "1.0.0"
        }


# Instancia global
scanner = AISecurityScanner()
