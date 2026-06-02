import jsPDF from "jspdf";

export function generatePdfReport(
  simulation: any
) {
  const pdf = new jsPDF();

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

  let y = 20;

  pdf.setFontSize(22);
  pdf.text(
    "SecureForge BAS Report",
    20,
    y
  );

  y += 15;

  pdf.setFontSize(12);

  pdf.text(
    `Simulation: ${simulation.name}`,
    20,
    y
  );

  y += 8;

  pdf.text(
    `Target: ${simulation.target}`,
    20,
    y
  );

  y += 8;

  pdf.text(
    `Status: ${simulation.status}`,
    20,
    y
  );

  y += 15;

  pdf.setFontSize(16);
  pdf.text(
    "SOC Validation",
    20,
    y
  );

  y += 10;

  pdf.setFontSize(12);

  pdf.text(
    `SOC Score: ${
      soc?.soc_score ?? "N/A"
    }`,
    20,
    y
  );

  y += 8;

  pdf.text(
    `Rating: ${
      soc?.rating ?? "N/A"
    }`,
    20,
    y
  );

  y += 8;

  pdf.text(
    `Risk Level: ${
      blindspots?.risk_level ??
      "N/A"
    }`,
    20,
    y
  );

  y += 15;

  pdf.setFontSize(16);

  pdf.text(
    "Findings",
    20,
    y
  );

  y += 10;

  pdf.setFontSize(10);

  findings.forEach(
    (
      finding: any,
      index: number
    ) => {
      if (y > 260) {
        pdf.addPage();
        y = 20;
      }

      pdf.text(
        `${index + 1}. ${
          finding.title
        }`,
        20,
        y
      );

      y += 6;

      pdf.text(
        `Severity: ${
          finding.severity
        }`,
        25,
        y
      );

      y += 6;

      pdf.text(
        `MITRE: ${
          finding.mitre_id
        }`,
        25,
        y
      );

      y += 8;
    }
  );

  pdf.save(
    `${simulation.name}.pdf`
  );
}