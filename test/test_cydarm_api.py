# File: test_cydarm_api.py
#
# Copyright (c) 2023 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#

import os
import random
from datetime import datetime
from random import randint

import pytest

from cydarm_api import CydarmAPI


@pytest.fixture
def cydarm_api_instance():
    base_url = os.environ["CYDARM_BASE_URL"]
    username = os.environ["CYDARM_USERNAME"]
    password = os.environ["CYDARM_PASSWORD"]
    yield CydarmAPI(base_url=base_url, username=username, password=password)


@pytest.fixture
def test_org():
    """Get organization name from environment or use default"""
    return os.environ.get("CYDARM_TEST_ORG", "SplunkAppDev")


@pytest.fixture
def test_case(cydarm_api_instance, test_org):
    """Create a test case and clean it up after the test"""
    case = cydarm_api_instance.create_case(
        description="Test Case - Created by Automated Tests",
        org=test_org
    )
    yield case
    # Note: Add cleanup when API supports deletion


@pytest.fixture
def test_playbook(cydarm_api_instance, acl_uuid):
    """Create a test playbook for testing"""
    playbook = cydarm_api_instance.create_playbook(
        name=f"Test Playbook {randint(100, 1000)}",
        description="Created by Automated Tests",
        acl_uuid=acl_uuid
    )
    yield playbook


@pytest.fixture
def test_action(cydarm_api_instance, acl_uuid):
    """Create a test action for testing"""
    action = cydarm_api_instance.create_playbook_action(
        name=f"Test Action {randint(100, 1000)}",
        description="Created by Automated Tests",
        acl_uuid=acl_uuid
    )
    yield action


@pytest.fixture
def test_case_playbook(cydarm_api_instance, test_case, test_playbook):
    """Create a test case playbook linking a case and playbook"""
    case_playbook = cydarm_api_instance.create_case_playbook(
        case_uuid=test_case["uuid"],
        playbook_uuid=test_playbook["uuid"]
    )
    yield case_playbook


@pytest.fixture
def acl_uuid():
    """Get ACL UUID from environment or use default"""
    return os.environ.get("CYDARM_TEST_ACL_UUID", "e26a30a0-2b4e-4d39-a1d3-5fd0792e6f84")


@pytest.fixture
def test_user_uuid():
    """Get test user UUID from environment"""
    uuid = os.environ.get("CYDARM_TEST_USER_UUID")
    if not uuid:
        pytest.skip("CYDARM_TEST_USER_UUID not set")
    return uuid


def test_get_bearer_token(cydarm_api_instance):
    token = cydarm_api_instance.generate_bearer_token()
    print(token)


def test_get_case(cydarm_api_instance, test_case):
    case = cydarm_api_instance.get_case(case_uuid=test_case["uuid"])
    assert case["uuid"] == test_case["uuid"]
    assert "description" in case
    assert "status" in case


def test_update_case(cydarm_api_instance, test_case):
    new_severity = random.randint(1, 5)
    cydarm_api_instance.update_case(case_uuid=test_case["uuid"], severity=new_severity)
    case = cydarm_api_instance.get_case(case_uuid=test_case["uuid"])
    assert case['severity'] == new_severity


def test_update_case_history(cydarm_api_instance):
    case = cydarm_api_instance.create_case(description="Test Case - Created by Automated Tests", org=test_org)
    case_uuid = case["uuid"]
    now = datetime.now().astimezone().isoformat()
    resp = cydarm_api_instance.update_case_history(case_uuid=case_uuid, modified=now, status="Event")
    # HTTP status: no content
    assert resp.status_code == 204


def test_add_watcher_to_case(cydarm_api_instance, test_case):
    user_uuid = os.environ.get("CYDARM_TEST_USER_UUID")
    if not user_uuid:
        pytest.skip("CYDARM_TEST_USER_UUID not set")
    cydarm_api_instance.add_watcher_to_case(
        case_uuid=test_case["uuid"],
        user_uuid=user_uuid
    )


def test_add_member_to_case(cydarm_api_instance, test_case, test_org):
    # Create a second case to be the member
    member_case = cydarm_api_instance.create_case(
        description="Member Test Case",
        org=test_org
    )
    resp = cydarm_api_instance.add_member_to_case(
        case_uuid=test_case["uuid"],
        member_case_uuid=member_case["uuid"]
    )
    assert "uuid" in resp


def test_get_cases_filtered_1(cydarm_api_instance):
    cases = cydarm_api_instance.get_cases_filtered(filter_text="Test")
    assert len(cases) > 0
    assert all("description" in case for case in cases)


def test_get_case_quick_search(cydarm_api_instance):
    cases = cydarm_api_instance.get_case_quick_search(search_string="CVE")
    assert len(cases) > 0
    first_case = cases[0]
    assert "uuid" in first_case
    assert "acl" in first_case


def test_get_playbook(cydarm_api_instance, test_playbook):
    playbook = cydarm_api_instance.get_playbook(playbook_uuid=test_playbook["uuid"])
    assert playbook["atc"]["uuid"] == test_playbook["uuid"]
    assert type(playbook["atc"]["actions"]) is list


def test_get_playbooks(cydarm_api_instance, test_case_playbook):
    playbooks = cydarm_api_instance.get_case_playbooks(case_uuid=test_case_playbook["caseUuid"])
    assert len(playbooks) >= 1
    assert all("playbookName" in playbook for playbook in playbooks)


def test_create_playbook(cydarm_api_instance, acl_uuid):
    playbook_name = f"Test playbook {randint(100, 1000)}"
    playbook = cydarm_api_instance.create_playbook(
        name=playbook_name,
        description="Test playbook",
        acl_uuid=acl_uuid
    )
    assert "uuid" in playbook
    assert "acl" in playbook


def test_create_action(cydarm_api_instance, acl_uuid):
    action_name = f"Test action {randint(100, 1000)}"
    action = cydarm_api_instance.create_playbook_action(
        name=action_name,
        description="action",
        acl_uuid=acl_uuid
    )
    assert "uuid" in action
    assert "acl" in action


def test_add_action_to_playbook(cydarm_api_instance, test_playbook, test_action):
    resp = cydarm_api_instance.add_action_to_playbook(
        playbook_uuid=test_playbook["uuid"],
        action_uuid=test_action["uuid"]
    )
    assert resp.status_code == 201


def test_get_playbook_action(cydarm_api_instance, test_action):
    action = cydarm_api_instance.get_playbook_action(action_uuid=test_action["uuid"])
    atc_obj = action["atc"]
    assert atc_obj["uuid"] == test_action["uuid"]
    assert atc_obj["name"] == test_action["name"]


def test_create_case_playbook(cydarm_api_instance, test_case, test_playbook):
    resp = cydarm_api_instance.create_case_playbook(
        playbook_uuid=test_playbook["uuid"],
        case_uuid=test_case["uuid"]
    )
    assert "uuid" in resp


def test_get_case_playbook(cydarm_api_instance, test_case_playbook):
    playbook = cydarm_api_instance.get_case_playbook(
        case_uuid=test_case_playbook["caseUuid"],
        case_playbook_uuid=test_case_playbook["casePlaybookUuid"]
    )
    assert playbook["caseUuid"] == test_case_playbook["caseUuid"]
    assert playbook["casePlaybookUuid"] == test_case_playbook["casePlaybookUuid"]


def test_add_comment_to_action_instance(cydarm_api_instance, test_case_playbook):
    # Get first action instance from the playbook
    action_instances = test_case_playbook.get("actionInstances", [])
    if not action_instances:
        pytest.skip("No action instances available")

    action_instance_uuid = action_instances[0]["uuid"]
    cydarm_api_instance.create_action_instance_data(
        action_instance_uuid=action_instance_uuid,
        comment="Test comment from automated tests"
    )


def test_create_case(cydarm_api_instance, test_org):
    resp = cydarm_api_instance.create_case(
        description="Created in Python",
        org=test_org
    )
    assert "uuid" in resp


def test_get_user(cydarm_api_instance, test_user_uuid):
    resp = cydarm_api_instance.get_user(user_uuid=test_user_uuid)
    assert "uuid" in resp
    assert "username" in resp  # Remove specific username assertion


def test_get_acl(cydarm_api_instance, acl_uuid):
    resp = cydarm_api_instance.get_acl(acl_uuid=acl_uuid)
    assert "description" in resp  # Remove specific description assertion


def test_add_and_remove_case_tag(cydarm_api_instance, test_org):
    created_case = cydarm_api_instance.create_case(description="Created in Python", org=test_org)
    case_uuid = created_case["uuid"]

    # assumes that "testing" is an existing tag
    cydarm_api_instance.add_case_tag(case_uuid=case_uuid, tag_value="testing")

    updated_case_1 = cydarm_api_instance.get_case(case_uuid)
    assert "testing" in updated_case_1["tags"]

    cydarm_api_instance.delete_case_tag(case_uuid=case_uuid, tag_value="testing")
    updated_case_2 = cydarm_api_instance.get_case(case_uuid)
    assert updated_case_2["tags"] == []


def test_add_comment_to_case(cydarm_api_instance, test_org):
    created_case = cydarm_api_instance.create_case(description="Created in Python", org=test_org)
    case_uuid = created_case["uuid"]
    cydarm_api_instance.create_case_data_comment(case_uuid=case_uuid, comment="hello from python")
    print(case_uuid)
    data_list = cydarm_api_instance.get_case_data_list(case_uuid=case_uuid)
    assert any([x["significance"] == "Comment" for x in data_list["case_data"]])


def test_create_case_data_file(cydarm_api_instance, test_org):
    created_case = cydarm_api_instance.create_case(description="Created in Python", org=test_org)
    case_uuid = created_case["uuid"]

    file_content = b"%PDF-1.4\n%Test PDF content"
    file_name = "test_document.pdf"
    mime_type = "application/pdf"

    resp = cydarm_api_instance.create_case_data_file(
        case_uuid=case_uuid,
        file_data=file_content,
        file_name=file_name,
        mime_type=mime_type
    )
    assert "uuid" in resp

    data_list = cydarm_api_instance.get_case_data_list(case_uuid=case_uuid)
    assert any([x["mimeType"] == mime_type and x["fileName"] == file_name for x in data_list["case_data"]])
