"""
Tests for the netsh firewall rule parser.

The parser is the fragile part of firewall management: netsh localizes both
its field labels and its values, and the console code page varies by machine.
These tests pin the behaviour against captured output in both languages.
"""

import pytest

from core.firewall_manager import FirewallManager, _decode

ENGLISH_OUTPUT = """
Rule Name:                            NetGuardian - Block Telnet
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            23
RemotePort:                           Any
Action:                               Block

Rule Name:                            Microsoft Edge (mDNS-In)
----------------------------------------------------------------------
Enabled:                              No
Direction:                            Out
Profiles:                             Public
Protocol:                             UDP
LocalPort:                            5353
Action:                               Allow
"""

PORTUGUESE_OUTPUT = """
Nome da Regra:                        NetGuardian - Bloquear Telnet
----------------------------------------------------------------------
Habilitado:                           Sim
Direção:                              Entrada
Perfis:                               Domínio,Particular,Público
LocalIP:                              Qualquer
Protocolo:                            TCP
LocalPort:                            23
Ação:                                 Bloquear

Nome da Regra:                        Microsoft Edge (mDNS-in)
----------------------------------------------------------------------
Habilitado:                           Não
Direção:                              Saída
Perfis:                               Público
Protocolo:                            Qualquer
LocalPort:                            Qualquer
Ação:                                 Permitir
"""


@pytest.fixture
def manager(monkeypatch):
    """A FirewallManager that does not shell out for the admin check."""
    monkeypatch.setattr(FirewallManager, "_admin_cache", True)
    return FirewallManager()


class TestParseEnglish:
    def test_parses_all_rules(self, manager):
        rules = manager._parse_rules(ENGLISH_OUTPUT, netguardian_only=False)
        assert len(rules) == 2

    def test_filters_to_netguardian_rules(self, manager):
        rules = manager._parse_rules(ENGLISH_OUTPUT, netguardian_only=True)
        assert len(rules) == 1
        assert rules[0].name == "NetGuardian - Block Telnet"

    def test_field_values(self, manager):
        rule = manager._parse_rules(ENGLISH_OUTPUT, netguardian_only=True)[0]
        assert rule.action == "Block"
        assert rule.protocol == "TCP"
        assert rule.port == "23"
        assert rule.direction == "Inbound"
        assert rule.enabled is True

    def test_direction_read_per_rule_not_per_call(self, manager):
        # One netsh dump contains both directions; each rule carries its own.
        rules = manager._parse_rules(ENGLISH_OUTPUT, netguardian_only=False)
        assert [r.direction for r in rules] == ["Inbound", "Outbound"]

    def test_disabled_rule(self, manager):
        rules = manager._parse_rules(ENGLISH_OUTPUT, netguardian_only=False)
        assert rules[1].enabled is False


class TestParsePortuguese:
    def test_parses_accented_labels(self, manager):
        rules = manager._parse_rules(PORTUGUESE_OUTPUT, netguardian_only=False)
        assert len(rules) == 2

    def test_localized_action_maps_to_english(self, manager):
        rules = manager._parse_rules(PORTUGUESE_OUTPUT, netguardian_only=False)
        assert rules[0].action == "Block"
        assert rules[1].action == "Allow"

    def test_localized_direction_maps_to_english(self, manager):
        rules = manager._parse_rules(PORTUGUESE_OUTPUT, netguardian_only=False)
        assert [r.direction for r in rules] == ["Inbound", "Outbound"]

    def test_localized_enabled_flag(self, manager):
        rules = manager._parse_rules(PORTUGUESE_OUTPUT, netguardian_only=False)
        assert rules[0].enabled is True
        assert rules[1].enabled is False

    def test_localized_any_normalized(self, manager):
        rules = manager._parse_rules(PORTUGUESE_OUTPUT, netguardian_only=False)
        assert rules[1].protocol == "Any"
        assert rules[1].port == "Any"

    def test_prefix_filter_works_on_localized_output(self, manager):
        rules = manager._parse_rules(PORTUGUESE_OUTPUT, netguardian_only=True)
        assert len(rules) == 1
        assert rules[0].name.startswith("NetGuardian")


class TestNormalize:
    @pytest.mark.parametrize("raw,expected", [
        ("Ação:", "acao:"),
        ("Direção:", "direcao:"),
        ("Habilitado:", "habilitado:"),
        ("Rule Name:", "rule name:"),
        ("Domínio", "dominio"),
    ])
    def test_strips_accents_and_case(self, raw, expected):
        assert FirewallManager._normalize(raw) == expected


class TestDecode:
    def test_prefers_utf8(self):
        assert _decode("Ação".encode("utf-8")) == "Ação"

    def test_falls_back_for_non_utf8(self):
        # cp850 bytes are not valid UTF-8; decoding must not raise.
        assert _decode("Ação".encode("cp850")) != ""

    def test_empty_input(self):
        assert _decode(b"") == ""


class TestEmptyAndMalformed:
    def test_empty_output(self, manager):
        assert manager._parse_rules("", netguardian_only=False) == []

    def test_output_with_no_rules(self, manager):
        text = "Ok.\n\nNo rules match the specified criteria.\n"
        assert manager._parse_rules(text, netguardian_only=False) == []
