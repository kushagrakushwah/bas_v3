import { jsPDF } from "jspdf";

export function generateMarkdownReport(simulations: any[]): string {
  let md = "# SecureForge Detailed Attack Simulation Report\n\n";
  md += `Generated on: ${new Date().toLocaleString()}\n\n`;
  md += `---\n\n`;

  if (simulations.length === 0) {
    return md + "No simulations selected or available.";
  }

  simulations.forEach((sim) => {
    md += `## Simulation: ${sim.name}\n`;
    md += `- **Status**: ${sim.status}\n`;
    md += `- **Target**: ${sim.target}\n`;
    md += `- **Started**: ${new Date(sim.started_at.endsWith('Z') ? sim.started_at : sim.started_at + 'Z').toLocaleString('en-US', { timeZone: 'Asia/Kolkata' })}\n\n`;

    const findings = sim.module_results?.flatMap((res: any) => res.findings || []) || [];

    if (findings.length === 0) {
      md += `*No findings detected during this simulation.*\n\n`;
    } else {
      md += `### Detailed Findings (${findings.length})\n\n`;
      findings.forEach((finding: any, idx: number) => {
        md += `#### ${idx + 1}. ${finding.title}\n`;
        md += `- **Severity**: ${finding.severity.toUpperCase()}\n`;
        md += `- **Target**: ${finding.target || 'N/A'}\n`;
        md += `- **MITRE ID**: ${finding.mitre_id || 'N/A'}\n`;
        md += `- **Triggering Module**: ${finding.module || 'Unknown'}\n`;
        if (finding.evidence) {
          md += `- **Payload / Evidence**: \`${finding.evidence}\`\n`;
        }
        md += `\n**Description**:\n${finding.description || 'No description provided.'}\n\n`;
        if (finding.remediation) {
          md += `**Remediation**:\n${finding.remediation}\n\n`;
        }
        md += `---\n\n`;
      });
    }
  });

  return md;
}

export function generatePDFReport(simulations: any[]) {
  const doc = new jsPDF();
  let yPos = 20;
  const pageHeight = doc.internal.pageSize.height;
  const margin = 15;
  const maxWidth = 180;

  const checkPageBreak = (neededHeight: number) => {
    if (yPos + neededHeight >= pageHeight - margin) {
      doc.addPage();
      yPos = 20;
    }
  };

  doc.setFontSize(18);
  doc.setTextColor(220, 38, 38); // Red color for title
  doc.text("SecureForge Attack Simulation Report", margin, yPos);
  yPos += 10;
  
  doc.setFontSize(10);
  doc.setTextColor(100, 100, 100);
  doc.text(`Generated on: ${new Date().toLocaleString()}`, margin, yPos);
  yPos += 15;

  if (simulations.length === 0) {
    doc.text("No simulations selected.", margin, yPos);
    doc.save("SecureForge_Report.pdf");
    return;
  }

  simulations.forEach((sim) => {
    checkPageBreak(30);
    doc.setFontSize(14);
    doc.setTextColor(0, 0, 0);
    doc.text(`Simulation: ${sim.name}`, margin, yPos);
    yPos += 8;

    doc.setFontSize(11);
    doc.setTextColor(50, 50, 50);
    doc.text(`Status: ${sim.status} | Target: ${sim.target}`, margin, yPos);
    yPos += 10;

    const findings = sim.module_results?.flatMap((res: any) => res.findings || []) || [];

    if (findings.length === 0) {
      doc.text("No findings detected.", margin, yPos);
      yPos += 15;
    } else {
      findings.forEach((finding: any, idx: number) => {
        checkPageBreak(50);
        
        doc.setFontSize(12);
        doc.setTextColor(150, 0, 0); // Dark red for finding title
        doc.text(`${idx + 1}. ${finding.title}`, margin, yPos);
        yPos += 6;

        doc.setFontSize(10);
        doc.setTextColor(0, 0, 0);
        doc.text(`Severity: ${finding.severity.toUpperCase()}  |  Module: ${finding.module}`, margin, yPos);
        yPos += 5;
        doc.text(`Target: ${finding.target || 'N/A'}  |  MITRE ID: ${finding.mitre_id}`, margin, yPos);
        yPos += 8;

        if (finding.evidence) {
          doc.setFont("helvetica", "bold");
          doc.text("Payload / Evidence:", margin, yPos);
          doc.setFont("helvetica", "normal");
          yPos += 5;
          const evidenceLines = doc.splitTextToSize(String(finding.evidence), maxWidth);
          doc.text(evidenceLines, margin, yPos);
          yPos += (evidenceLines.length * 5) + 3;
        }

        doc.setFont("helvetica", "bold");
        doc.text("Details:", margin, yPos);
        doc.setFont("helvetica", "normal");
        yPos += 5;
        
        // Strip HTML from description for PDF text
        const tempDiv = document.createElement("div");
        tempDiv.innerHTML = finding.description || "";
        const cleanDesc = tempDiv.textContent || tempDiv.innerText || "";
        
        const descLines = doc.splitTextToSize(cleanDesc, maxWidth);
        doc.text(descLines, margin, yPos);
        yPos += (descLines.length * 5) + 5;

        if (finding.remediation) {
            checkPageBreak(20);
            doc.setFont("helvetica", "bold");
            doc.text("Remediation:", margin, yPos);
            doc.setFont("helvetica", "normal");
            yPos += 5;
            const remLines = doc.splitTextToSize(finding.remediation, maxWidth);
            doc.text(remLines, margin, yPos);
            yPos += (remLines.length * 5) + 10;
        } else {
            yPos += 5;
        }
        
        // Draw separator
        doc.setDrawColor(200, 200, 200);
        doc.line(margin, yPos - 5, 210 - margin, yPos - 5);
      });
    }
    yPos += 10;
  });

  doc.save("SecureForge_Detailed_Report.pdf");
}
