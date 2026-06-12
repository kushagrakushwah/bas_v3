
from .ssh_bruteforce import SSHBruteForceModule
from .owasp_web import OWASPWebModule
from .privilege_escalation import PrivEscModule
from .waf_detection import WAFEvasionModule
from .nmap_scan import NmapScanModule
from .apt_killchain import APTKillChainModule
from .recon_exposure import ReconExposureModule
from .impact_sim import ImpactSimModule



MODULE_REGISTRY = {
    SSHBruteForceModule.MODULE_NAME:      SSHBruteForceModule,
    OWASPWebModule.MODULE_NAME:           OWASPWebModule,
    PrivEscModule.MODULE_NAME:            PrivEscModule,
    WAFEvasionModule.MODULE_NAME:         WAFEvasionModule,
    ReconExposureModule.MODULE_NAME:      ReconExposureModule,
    ImpactSimModule.MODULE_NAME:          ImpactSimModule,
    NmapScanModule.MODULE_NAME:           NmapScanModule,
    APTKillChainModule.MODULE_NAME:       APTKillChainModule,
}

