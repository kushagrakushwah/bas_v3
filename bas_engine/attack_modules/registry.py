
try:
    from .ssh_bruteforce import SSHBruteForceModule
except ImportError:
    SSHBruteForceModule = None
from .owasp_web import OWASPWebModule
from .privilege_escalation_safe import PrivEscModule
from .waf_detection import WAFDetectionModule
from .nmap_scan import NmapScanModule
from .apt_killchain import APTKillChainModule
from .recon_exposure import ReconExposureModule
from .impact_sim_safe import ImpactSimModule
from .vuln_scanner import VulnScannerModule

MODULE_REGISTRY = {
    OWASPWebModule.MODULE_NAME:           OWASPWebModule,
    PrivEscModule.MODULE_NAME:            PrivEscModule,
    WAFDetectionModule.MODULE_NAME:         WAFDetectionModule,
    ReconExposureModule.MODULE_NAME:      ReconExposureModule,
    ImpactSimModule.MODULE_NAME:          ImpactSimModule,
    NmapScanModule.MODULE_NAME:           NmapScanModule,
    APTKillChainModule.MODULE_NAME:       APTKillChainModule,
    VulnScannerModule.MODULE_NAME:        VulnScannerModule,
}

if SSHBruteForceModule:
    MODULE_REGISTRY[SSHBruteForceModule.MODULE_NAME] = SSHBruteForceModule
