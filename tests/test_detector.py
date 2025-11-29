import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.detector import ReentrancyDetector
from src.models import Severity, VulnerabilityType


class TestReentrancyDetector:

    def test_detect_state_change_after_call(self):
        source = '''
        contract Vulnerable {
            mapping(address => uint256) public balances;

            function withdraw(uint256 amount) external {
                require(balances[msg.sender] >= amount);
                (bool success, ) = msg.sender.call{value: amount}("");
                require(success);
                balances[msg.sender] -= amount;
            }
        }
        '''
        detector = ReentrancyDetector()
        result = detector.analyze_source(source)

        critical_vulns = [v for v in result.vulnerabilities
                         if v.severity == Severity.CRITICAL]
        assert len(critical_vulns) >= 1
        assert critical_vulns[0].vuln_type == VulnerabilityType.STATE_CHANGE_AFTER_CALL

    def test_detect_call_in_loop(self):
        source = '''
        contract LoopVuln {
            function batchSend(address[] calldata recipients) external {
                for (uint i = 0; i < recipients.length; i++) {
                    recipients[i].call{value: 1 ether}("");
                }
            }
        }
        '''
        detector = ReentrancyDetector()
        result = detector.analyze_source(source)

        loop_vulns = [v for v in result.vulnerabilities
                      if v.vuln_type == VulnerabilityType.EXTERNAL_CALL_IN_LOOP]
        assert len(loop_vulns) >= 1

    def test_safe_contract_no_critical(self):
        source = '''
        contract Safe {
            mapping(address => uint256) public balances;

            function withdraw(uint256 amount) external {
                require(balances[msg.sender] >= amount);
                balances[msg.sender] -= amount;
                (bool success, ) = msg.sender.call{value: amount}("");
                require(success);
            }
        }
        '''
        detector = ReentrancyDetector()
        result = detector.analyze_source(source)

        critical_vulns = [v for v in result.vulnerabilities
                         if v.severity == Severity.CRITICAL]
        assert len(critical_vulns) == 0

    def test_delegatecall_detection(self):
        source = '''
        contract DelegateVuln {
            function execute(address target, bytes calldata data) external {
                target.delegatecall(data);
            }
        }
        '''
        detector = ReentrancyDetector()
        result = detector.analyze_source(source)

        delegate_vulns = [v for v in result.vulnerabilities
                         if v.vuln_type == VulnerabilityType.DELEGATECALL_REENTRANCY]
        assert len(delegate_vulns) >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
    