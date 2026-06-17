
from .ssh_bruteforce import SSHBruteForceModule
from .owasp_web import OWASPWebModule
from .privilege_escalation_safe import PrivEscModule
from .waf_detection import WAFEvasionModule
from .nmap_scan import NmapScanModule
from .apt_killchain import APTKillChainModule
from .recon_exposure import ReconExposureModule
from .impact_sim_safe import ImpactSimModule
from .custom_http import CustomHTTPModule


MODULE_REGISTRY = {
    SSHBruteForceModule.MODULE_NAME:      SSHBruteForceModule,
    OWASPWebModule.MODULE_NAME:           OWASPWebModule,
    PrivEscModule.MODULE_NAME:            PrivEscModule,
    WAFEvasionModule.MODULE_NAME:         WAFEvasionModule,
    ReconExposureModule.MODULE_NAME:      ReconExposureModule,
    ImpactSimModule.MODULE_NAME:          ImpactSimModule,
    NmapScanModule.MODULE_NAME:           NmapScanModule,
    APTKillChainModule.MODULE_NAME:       APTKillChainModule,
    CustomHTTPModule.MODULE_NAME: CustomHTTPModule,
}

