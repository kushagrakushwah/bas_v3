export function buildExecutiveReport(
  simulation: any
) {
  const soc =
    simulation?.metadata
      ?.detection_validation
      ?.soc_score;

  const blindspots =
    simulation?.metadata
      ?.detection_validation
      ?.blindspots;

  const findings =
    simulation?.module_results?.flatMap(
      (result: any) =>
        result.findings || []
    ) || [];

  return `
SECUREFORGE BAS EXECUTIVE REPORT
================================

Simulation:
${simulation.name}

Target:
${simulation.target}

Status:
${simulation.status}

SOC Score:
${soc?.soc_score ?? "N/A"}

Rating:
${soc?.rating ?? "N/A"}

Coverage Strength:
${soc?.coverage_strength ?? "N/A"}

Risk Level:
${blindspots?.risk_level ?? "N/A"}

Blind Spots:
${blindspots?.blind_spot_count ?? 0}

Coverage:
${blindspots?.coverage_percent ?? 0}%

================================
FINDINGS
================================

${findings
  .map(
    (finding: any) => `
Title: ${finding.title}
Severity: ${finding.severity}
MITRE ID: ${finding.mitre_id}
Description: ${finding.description}
`
  )
  .join("\n")}
`;
}