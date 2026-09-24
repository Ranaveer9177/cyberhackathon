#![allow(dead_code)]

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceTier {
    ConfirmedFinding, // Confirmed source, trace, sink, and no sanitizer -> HIGH confidence
    PotentialIssue,   // Suspect sink without full source provenance -> MEDIUM confidence
    Informational,    // Low-risk hygiene, test credential, or advisory -> LOW confidence
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub tier: EvidenceTier,
    pub confidence: &'static str, // "HIGH", "MEDIUM", "LOW"
    pub is_constant: bool,
    pub is_verified: bool,
    pub rationale: String,
}

pub struct FindingVerificationEngine;

impl FindingVerificationEngine {
    /// Determines whether a string expression is a compile-time constant or literal string.
    pub fn is_literal_constant(expr: &str) -> bool {
        let trimmed = expr.trim();
        // Plain string literal e.g. "echo hello" or 'ls -la'
        (trimmed.starts_with('"')
            && trimmed.ends_with('"')
            && !trimmed.contains('{')
            && !trimmed.contains('%'))
            || (trimmed.starts_with('\'')
                && trimmed.ends_with('\'')
                && !trimmed.contains('{')
                && !trimmed.contains('%'))
    }

    /// Evaluates evidence to assign tier and confidence.
    pub fn verify(
        has_untrusted_source: bool,
        has_provenance_flow: bool,
        has_dangerous_sink: bool,
        has_sanitizer: bool,
        is_literal: bool,
    ) -> VerificationResult {
        if is_literal {
            return VerificationResult {
                tier: EvidenceTier::Informational,
                confidence: "LOW",
                is_constant: true,
                is_verified: false,
                rationale: "Sink consumes a compile-time constant literal; injection not possible."
                    .to_string(),
            };
        }

        if has_sanitizer {
            return VerificationResult {
                tier: EvidenceTier::Informational,
                confidence: "LOW",
                is_constant: false,
                is_verified: false,
                rationale: "Data flow passes through a recognized sanitizer for this sink."
                    .to_string(),
            };
        }

        if has_untrusted_source && has_dangerous_sink {
            if has_provenance_flow {
                VerificationResult {
                    tier: EvidenceTier::ConfirmedFinding,
                    confidence: "HIGH",
                    is_constant: false,
                    is_verified: true,
                    rationale: "Complete end-to-end data flow confirmed from untrusted source to dangerous sink.".to_string(),
                }
            } else {
                VerificationResult {
                    tier: EvidenceTier::PotentialIssue,
                    confidence: "MEDIUM",
                    is_constant: false,
                    is_verified: true,
                    rationale: "Untrusted source and dangerous sink detected in scope, but path is heuristic.".to_string(),
                }
            }
        } else if has_dangerous_sink {
            VerificationResult {
                tier: EvidenceTier::PotentialIssue,
                confidence: "MEDIUM",
                is_constant: false,
                is_verified: false,
                rationale: "Dangerous sink invoked with non-constant variable of unknown origin."
                    .to_string(),
            }
        } else {
            VerificationResult {
                tier: EvidenceTier::Informational,
                confidence: "LOW",
                is_constant: false,
                is_verified: false,
                rationale: "Insufficient evidence to confirm vulnerability.".to_string(),
            }
        }
    }
}
