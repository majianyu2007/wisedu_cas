"""Tests for CAS HTML parsing utilities."""

import pytest

from wisedu_cas.exceptions import ParseError
from wisedu_cas.parser import (
    body_contains_cas_fields,
    extract_error_text,
    parse_login_form,
)


class TestParseLoginForm:
    def test_extracts_execution_and_salt(self) -> None:
        html = '''
        <html>
        <input type="hidden" id="execution" name="execution" value="abc123-exec"/>
        <input type="hidden" id="pwdEncryptSalt" name="pwdEncryptSalt" value="salt9876"/>
        </html>
        '''
        execution, salt = parse_login_form(html)
        assert execution == "abc123-exec"
        assert salt == "salt9876"

    def test_alternative_quote_style(self) -> None:
        html = """
        <input id='execution' value='exec-single' />
        <input id='pwdEncryptSalt' value='salt-single' />
        """
        execution, salt = parse_login_form(html)
        assert execution == "exec-single"
        assert salt == "salt-single"

    def test_missing_execution_raises_parse_error(self) -> None:
        html = '<input id="pwdEncryptSalt" value="salt"/>'
        with pytest.raises(ParseError):
            parse_login_form(html)

    def test_missing_salt_raises_parse_error(self) -> None:
        html = '<input id="execution" value="exec"/>'
        with pytest.raises(ParseError):
            parse_login_form(html)

    def test_malformed_html_still_parses(self) -> None:
        html = '''
        <div><input class="foo" id="execution" value="tok" disabled/>
        <span><input id="pwdEncryptSalt" value="slt"/></span></div>
        '''
        execution, salt = parse_login_form(html)
        assert execution == "tok"
        assert salt == "slt"


class TestExtractErrorText:
    def test_extracts_error_message(self) -> None:
        html = '''
        <div id="formErrorTip">
        <span>密码错误，请重新输入</span>
        </div>
        '''
        msg = extract_error_text(html)
        assert msg == "密码错误，请重新输入"

    def test_returns_none_when_no_error(self) -> None:
        html = '<div>Normal page content</div>'
        assert extract_error_text(html) is None


class TestBodyContainsCasFields:
    def test_detects_cas_form(self) -> None:
        html = '''
        <html><body>
        <input id="execution" value="e1"/>
        <input id="pwdEncryptSalt" value="s1"/>
        </body></html>
        '''
        assert body_contains_cas_fields(html.encode()) is True

    def test_rejects_non_cas_body(self) -> None:
        html = '<html><body>Welcome!</body></html>'
        assert body_contains_cas_fields(html.encode()) is False

    def test_only_execution_not_enough(self) -> None:
        html = '<input id="execution" value="e1"/>'
        assert body_contains_cas_fields(html.encode()) is False
