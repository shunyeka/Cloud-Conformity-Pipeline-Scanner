import os
import json
import pytest
import logging

from scanner import CcValidator


def test_env_vars(set_env_vars):
    """
    GIVEN `CcValidator` is instantiated
    WHEN all suitable variables are passed
    THEN don't raise an error
    """
    CcValidator()


def test_missing_env_vars(caplog, monkeypatch):
    """
    GIVEN `CcValidator` is instantiated
    WHEN one or more env vars are not provided
    THEN exit with an error of 1
    """

    monkeypatch.delenv("CFN_TEMPLATE_FILE_LOCATION")

    with pytest.raises(SystemExit):
        CcValidator()

    assert "Please ensure all environment variables are set" in caplog.text


def test_invalid_region(caplog, monkeypatch):
    """
    GIVEN `CcValidator` is instantiated
    WHEN an invalid CC region is provided
    THEN exit with an error of 1
    """

    monkeypatch.setenv("CC_REGION", "x")

    with pytest.raises(SystemExit):
        CcValidator()

    assert 'Please ensure "CC_REGION" is set to a region which is supported by Conformity' in caplog.text


def test_invalid_level(caplog, monkeypatch):
    """
    GIVEN `CcValidator` is instantiated
    WHEN an invalid rule severity level is provided
    THEN exit with an error of 1
    """

    monkeypatch.setenv("CC_RISK_LEVEL", "x")

    with pytest.raises(SystemExit):
        CcValidator()

    assert "Unknown risk level. Please use one of LOW | MEDIUM | HIGH | VERY_HIGH | EXTREME" in caplog.text


def test_read_template_file_invalid_file(caplog, monkeypatch):
    """
    GIVEN `read_template_file` is called
    WHEN a non existent file is provided
    THEN exit with an error of 1
    """

    monkeypatch.setenv("CFN_TEMPLATE_FILE_LOCATION", "/tmp/x.yaml")

    c = CcValidator()

    with pytest.raises(SystemExit):
        c.read_template_file()

    assert "Template file does not exist" in caplog.text


def test_read_template_file_valid_file():
    """
    GIVEN `read_template_file` is called
    WHEN a file is provided
    THEN return the file contents as a string
    """

    c = CcValidator()
    template_str = c.read_template_file()

    assert "Resources" in template_str


def test_generate_payload():
    """
    GIVEN `generate_payload` is called
    WHEN a valid template is provided
    THEN return the payload which will be sent to Conformity
    """

    c = CcValidator()
    template_str = c.read_template_file()
    payload = c.generate_payload(template_str)

    assert "data" in payload


@pytest.mark.external
def test_run_validation_no_profile_id():
    """
    GIVEN `run_validation` is called
    WHEN no profile ID is provided
    THEN return the payload provided by Conformity
    """

    c = CcValidator()
    template_str = c.read_template_file()
    payload = c.generate_payload(template_str)
    validation = c.run_validation(payload)

    assert "data" in validation


@pytest.mark.external
def test_run_validation_valid_profile_id():
    """
    GIVEN `run_validation` is called
    WHEN a valid profile ID is provided
    THEN return the payload provided by Conformity
    """

    # ensure a valid profile ID is provided
    if not os.environ.get("CC_PROFILE_ID"):
        assert False is True

    c = CcValidator()
    template_str = c.read_template_file()
    payload = c.generate_payload(template_str)
    validation = c.run_validation(payload)

    assert "data" in validation


@pytest.mark.external
def test_run_validation_invalid_profile_id(monkeypatch):
    """
    GIVEN `run_validation` is called
    WHEN an invalid profile ID is provided
    THEN exit with an error of 1
    """

    monkeypatch.setenv("CC_PROFILE_ID", "x")

    c = CcValidator()
    template_str = c.read_template_file()
    payload = c.generate_payload(template_str)
    validation = c.run_validation(payload)

    assert "errors" in validation


@pytest.mark.external
def test_run_validation_invalid_api_key(caplog, monkeypatch):
    """
    GIVEN `run_validation` is called
    WHEN an invalid API key is provided
    THEN exit with an error of 1
    """

    monkeypatch.setenv("CC_API_KEY", "x")

    c = CcValidator()
    template_str = c.read_template_file()
    payload = c.generate_payload(template_str)

    with pytest.raises(SystemExit):
        c.run_validation(payload)

    assert "User is not authorized to access this resource with an explicit deny" in caplog.text


def test_get_results_pass(conformity_report):
    """
    GIVEN `get_results` is called
    WHEN no offending entries are found
    THEN return empty list (no security issues found)
    """

    c = CcValidator()
    report = c.get_results(conformity_report)
    assert not report


def test_get_results_fail(monkeypatch, conformity_report):
    """
    GIVEN `get_results` is called
    WHEN offending entries are found
    THEN return a `list` of failed entries
    """

    monkeypatch.setenv("CC_RISK_LEVEL", "LOW")

    c = CcValidator()
    report = c.get_results(conformity_report)
    assert report


def test_fail_pipeline_disabled(monkeypatch):
    """
    GIVEN `_fail_pipeline` is called
    WHEN `FAIL_PIPELINE` is `disabled`
    THEN return `False` (pipeline won't fail even if issues are found)
    """

    monkeypatch.setenv("FAIL_PIPELINE", "disabled")

    c = CcValidator()

    # real template not required for testing
    fail_pipeline = c._fail_pipeline("")

    assert fail_pipeline is False


def test_fail_pipeline_enabled():
    """
    GIVEN `_fail_pipeline` is called
    WHEN `FAIL_PIPELINE` is anything other than `disabled`
    THEN return `False` (pipeline will fail when issues are found)
    """

    c = CcValidator()

    # real template not required for testing
    fail_pipeline = c._fail_pipeline("")

    assert fail_pipeline is True


def test_fail_pipeline_template_files(monkeypatch, disabled_failed_pipeline_templates):
    """
    GIVEN `_fail_pipeline` is called
    WHEN `FAIL_PIPELINE_CFN` env var is `enabled` and `FailConformityPipeline` CFN parameter is `disabled`
    THEN return `False` (pipeline won't fail even if issues are found)
    """

    # override default valid template file path
    monkeypatch.setenv("CFN_TEMPLATE_FILE_LOCATION", disabled_failed_pipeline_templates)

    monkeypatch.setenv("FAIL_PIPELINE_CFN", "enabled")

    with open(disabled_failed_pipeline_templates, "r") as f:
        cfn_contents = f.read()

    c = CcValidator()
    fail_pipeline = c._fail_pipeline(cfn_contents)
    assert fail_pipeline is False


def test_fail_pipeline_invalid_template_filename(caplog, monkeypatch, tmp_path):
    """
    GIVEN `_fail_pipeline` is called
    WHEN `FAIL_PIPELINE_CFN` env var is `enabled` but an invalid filename is passed in
    THEN exit with an error of 1
    """
    d = tmp_path / "sub"
    d.mkdir()
    template_file_path = d / "x.txt"

    # override default valid template file path
    monkeypatch.setenv("CFN_TEMPLATE_FILE_LOCATION", str(template_file_path))

    monkeypatch.setenv("FAIL_PIPELINE_CFN", "enabled")

    c = CcValidator()

    with pytest.raises(SystemExit):
        c._fail_pipeline("")

    assert "Unknown file extension for template" in caplog.text


def test_check_fail_pipeline_unset(monkeypatch, template_dir):
    """
    GIVEN a valid template is passed in
    WHEN `FAIL_PIPELINE_CFN` env var is `enabled` but `FailConformityPipeline` CFN parameter is not set
    THEN return `True` (pipeline will fail when issues are found)
    """
    monkeypatch.setenv("FAIL_PIPELINE_CFN", "enabled")
    template_name = f"{template_dir}/insecure-s3-bucket.json"

    with open(template_name, "r") as f:
        cfn_contents = json.load(f)

    c = CcValidator()
    fail_pipeline = c._check_fail_pipeline(cfn_contents)
    assert fail_pipeline is True


def test_check_fail_pipeline_disabled(monkeypatch, template_dir):
    """
    GIVEN a valid template is passed in
    WHEN `FAIL_PIPELINE_CFN` env var is `enabled` and `FailConformityPipeline` CFN parameter is `disabled`
    THEN return `False` (pipeline won't fail even if issues are found)
    """
    monkeypatch.setenv("FAIL_PIPELINE_CFN", "enabled")
    template_name = f"{template_dir}/insecure-s3-bucket-disable-failure.json"

    with open(template_name, "r") as f:
        cfn_contents = json.load(f)

    c = CcValidator()
    fail_pipeline = c._check_fail_pipeline(cfn_contents)
    assert fail_pipeline is False


def test_check_fail_pipeline_invalid(monkeypatch, template_dir):
    """
    GIVEN a valid template is passed in
    WHEN `FAIL_PIPELINE_CFN` env var is `enabled` and but `FailConformityPipeline` CFN parameter is set to something other than "disabled"
    THEN return `True` (pipeline will fail when issues are found)
    """
    monkeypatch.setenv("FAIL_PIPELINE_CFN", "enabled")
    template_name = f"{template_dir}/insecure-s3-bucket-disable-failure.json"

    with open(template_name, "r") as f:
        cfn_contents = json.load(f)

    cfn_contents["Parameters"]["FailConformityPipeline"] = "x"

    c = CcValidator()
    fail_pipeline = c._check_fail_pipeline(cfn_contents)

    assert fail_pipeline is True


@pytest.mark.external
def test_run_secure_template(caplog):
    """
    GIVEN a valid template is passed in
    WHEN the template has no security issues
    THEN exit with a code of 0
    """
    caplog.set_level(logging.DEBUG)

    c = CcValidator()

    with pytest.raises(SystemExit):
        c.run()

    assert "No offending entries found" in caplog.text


@pytest.mark.external
def test_run_insecure_template(caplog, monkeypatch, template_dir):
    """
    GIVEN a valid template is passed in
    WHEN the template has security issues
    THEN exit with an error code of 1 and the failing rules
    """

    insecure_file_path = f"{template_dir}/insecure-s3-bucket.json"

    monkeypatch.setenv("CFN_TEMPLATE_FILE_LOCATION", insecure_file_path)

    c = CcValidator()

    with pytest.raises(SystemExit):
        c.run()

    assert "offending entries found" in caplog.text


@pytest.mark.external
def test_run_insecure_template_fail_pipeline_disabled(caplog, monkeypatch, template_dir):
    """
    GIVEN a valid template is passed in
    WHEN the template has security issues but the `FAIL_PIPELINE` environment variable is set to "disabled"
    THEN exit with a code of 0 and the failing rules
    """
    caplog.set_level(logging.INFO)

    insecure_file_path = f"{template_dir}/insecure-s3-bucket.json"

    monkeypatch.setenv("FAIL_PIPELINE", "disabled")
    monkeypatch.setenv("CFN_TEMPLATE_FILE_LOCATION", insecure_file_path)
    print(insecure_file_path)

    c = CcValidator()

    with pytest.raises(SystemExit):
        c.run()

    assert "Pipeline failure has been disabled" in caplog.text


@pytest.mark.external
def test_run_insecure_template_fail_pipeline_cfn_disabled(caplog, monkeypatch, template_dir):
    """
    GIVEN a valid template is passed in
    WHEN the template has security issues but the `FAIL_PIPELINE_CFN` env var is `enabled` and the `FailConformityPipeline` CFN param is `disabled`
    THEN exit with a code of 0 and the failing rules
    """
    caplog.set_level(logging.INFO)

    insecure_file_path = f"{template_dir}/insecure-s3-bucket-disable-failure.json"

    monkeypatch.setenv("FAIL_PIPELINE_CFN", "enabled")
    monkeypatch.setenv("CFN_TEMPLATE_FILE_LOCATION", insecure_file_path)
    print(insecure_file_path)

    c = CcValidator()

    with pytest.raises(SystemExit):
        c.run()

    assert "Pipeline failure has been disabled" in caplog.text


@pytest.mark.external
def test_run_insecure_template_fail_pipeline_enabled_cfn_disabled(caplog, monkeypatch, template_dir):
    """
    GIVEN a valid template is passed in
    WHEN the template has security issues and the `FAIL_PIPELINE_CFN` env var is `enabled` but the `FailConformityPipeline` CFN param is `disabled`
    THEN exit with an error of 1 and the failing rules
    """
    caplog.set_level(logging.INFO)

    insecure_file_path = f"{template_dir}/insecure-s3-bucket-disable-failure.json"

    monkeypatch.setenv("FAIL_PIPELINE_CFN", "disabled")
    monkeypatch.setenv("CFN_TEMPLATE_FILE_LOCATION", insecure_file_path)
    print(insecure_file_path)

    c = CcValidator()

    with pytest.raises(SystemExit):
        c.run()

    assert "offending entries found" in caplog.text
