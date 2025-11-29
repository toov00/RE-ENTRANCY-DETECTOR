import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.parser import SolidityParser


class TestSolidityParser:

    def test_parse_simple_contract(self):
        source = '''
        contract Simple {
            uint256 public value;

            function setValue(uint256 _value) public {
                value = _value;
            }
        }
        '''
        parser = SolidityParser()
        contracts = parser.parse(source)

        assert len(contracts) == 1
        assert contracts[0].name == 'Simple'
        assert len(contracts[0].functions) == 1
        assert contracts[0].functions[0].name == 'setValue'

    def test_parse_external_calls(self):
        source = '''
        contract WithCalls {
            function makeCall(address target) external {
                target.call{value: 1 ether}("");
            }

            function makeTransfer(address payable target) external {
                target.transfer(1 ether);
            }
        }
        '''
        parser = SolidityParser()
        contracts = parser.parse(source)

        assert len(contracts) == 1
        for func in contracts[0].functions:
            assert len(func.external_calls) == 1

    def test_parse_state_variables(self):
        source = '''
        contract WithState {
            uint256 public balance;
            mapping(address => uint256) public balances;
            address private owner;

            function updateBalance(uint256 amount) external {
                balance = amount;
            }
        }
        '''
        parser = SolidityParser()
        contracts = parser.parse(source)

        assert 'balance' in contracts[0].state_variables
        assert 'balances' in contracts[0].state_variables

    def test_detect_loop(self):
        source = '''
        contract WithLoop {
            function loopCall(address[] calldata targets) external {
                for (uint i = 0; i < targets.length; i++) {
                    targets[i].call("");
                }
            }
        }
        '''
        parser = SolidityParser()
        contracts = parser.parse(source)

        func = contracts[0].functions[0]
        assert len(func.external_calls) == 1
        assert func.external_calls[0].in_loop is True

    def test_parse_modifiers(self):
        source = '''
        contract WithModifiers {
            bool locked;
            modifier nonReentrant() {
                require(!locked);
                locked = true;
                _;
                locked = false;
            }

            function protected() external nonReentrant {
                msg.sender.call("");
            }
        }
        '''
        parser = SolidityParser()
        contracts = parser.parse(source)

        func = contracts[0].functions[0]
        assert 'nonReentrant' in func.modifiers

    def test_parse_inheritance(self):
        source = '''
        contract Base {}
        contract Child is Base {
            function test() external {}
        }
        '''
        parser = SolidityParser()
        contracts = parser.parse(source)

        child = [c for c in contracts if c.name == 'Child'][0]
        assert 'Base' in child.inherits


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
    