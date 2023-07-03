"""
copyright: Copyright (C) 2015-2023, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the stats can be obtained from the API and if they follow the expected schema.
       The Wazuh API is an open source 'RESTful' API that allows for interaction with the Wazuh manager from
       a web browser, command line tool like 'cURL' or any script or program that can make web requests.

components:
    - api

suite: config

targets:
    - manager

daemons:
    - wazuh-apid
    - wazuh-modulesd
    - wazuh-analysisd
    - wazuh-execd
    - wazuh-db
    - wazuh-remoted

os_platform:
    - linux

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - CentOS 6
    - Ubuntu Focal
    - Ubuntu Bionic
    - Ubuntu Xenial
    - Ubuntu Trusty
    - Debian Buster
    - Debian Stretch
    - Debian Jessie
    - Debian Wheezy
    - Red Hat 8
    - Red Hat 7
    - Red Hat 6

references:
    - https://documentation.wazuh.com/current/user-manual/api/reference.html (Get Wazuh daemon stats)
    - https://documentation.wazuh.com/current/user-manual/api/reference.html (Get Wazuh daemon stats from an agent)

tags:
    - api
"""
import jsonschema
import os
import pytest
import requests

from wazuh_testing.constants.api import DAEMONS_STATS_ROUTE
from wazuh_testing.modules.api.helpers import get_base_url, login
from wazuh_testing.tools.simulators.agent_simulator import create_agents, connect
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.utils.file import read_json_file
from wazuh_testing.utils.manage_agents import remove_agents

pytestmark = pytest.mark.server


# Generic vars
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')
STATISTICS_TEMPLATE_PATH = os.path.join(TEST_DATA_PATH, 'statistics_template')
daemons_handler_configuration = {'all_daemons': True}

# ------------------------------------------- TEST_MANAGER_STATISTICS_FORMAT -------------------------------------------
# Configuration and cases data
t1_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_manager_statistics_format.yaml')
t1_cases_path = os.path.join(TEST_CASES_PATH, 'manager_statistics_format_test_module',
                             'cases_manager_statistics_format.yaml')
t1_statistics_template_path = os.path.join(STATISTICS_TEMPLATE_PATH, 'manager_statistics_format_test_module')

# Manager statistics format test configurations (t1)
test1_configuration, test1_metadata, test1_cases_ids = get_test_cases_data(t1_cases_path)
test1_configuration = load_configuration_template(t1_configurations_path, test1_configuration, test1_metadata)

# -------------------------------------------- TEST_AGENT_STATISTICS_FORMAT --------------------------------------------
# Configuration and cases data
t2_cases_path = os.path.join(TEST_CASES_PATH, 'agent_statistics_format_test_module',
                             'cases_agent_statistics_format.yaml')
t2_statistics_template_path = os.path.join(STATISTICS_TEMPLATE_PATH, 'agent_statistics_format_test_module')

# Agent statistics format test configurations (t2)
test2_configuration, test2_metadata, test2_cases_ids = get_test_cases_data(t2_cases_path)


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('test_configuration,test_metadata', zip(test1_configuration, test1_metadata),
                         ids=test1_cases_ids)
def test_manager_statistics_format(test_configuration, test_metadata, load_wazuh_basic_configuration,
                                   set_wazuh_configuration, daemons_handler):
    """
    description: Check if the statistics returned by the API have the expected format.

    test_phases:
        - setup:
            - Load Wazuh light configuration
            - Apply ossec.conf configuration changes according to the configuration template and use case
            - Restart wazuh-manager service to apply configuration changes
        - test:
            - Request the statistics of a particular daemon from the API
            - Compare the obtained statistics with the json schema
        - tierdown:
            - Restore initial configuration
            - Stop wazuh-manager

    wazuh_min_version: 4.4.0

    parameters:
        - test_configuration:
            type: dict
            brief: Configuration data from the test case.
        - test_metadata:
            type: dict
            brief: Metadata from the test case.
        - load_wazuh_basic_configuration:
            type: fixture
            brief: Load basic wazuh configuration.
        - set_wazuh_configuration:
            type: fixture
            brief: Apply changes to the ossec.conf configuration.
        - daemons_handler:
            type: fixture
            brief: Wrapper of a helper function to handle Wazuh daemons.

    assertions:
        - Check if the statistics returned by the API have the expected format.

    input_description:
        - The `configuration_manager_statistics_format` file provides the module configuration for this test.
        - The `cases_manager_statistics_format` file provides the test cases.
    """
    endpoint = test_metadata['endpoint']
    statistics_schema_path = os.path.join(t1_statistics_template_path, f"{endpoint}_template.json")
    params = f"?daemons_list={endpoint}"
    url = get_base_url() + DAEMONS_STATS_ROUTE + params
    authentication_headers, _ = login()

    # Get daemon statistics
    response = requests.get(url, headers=authentication_headers, verify=False)
    stats_schema = read_json_file(statistics_schema_path)

    # Check if the API statistics response data meets the expected schema. Raise an exception if not.
    jsonschema.validate(instance=response.json(), schema=stats_schema)


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('test_metadata', test2_metadata, ids=test2_cases_ids)
def test_agent_statistics_format(test_metadata, daemons_handler):
    """
    description: Check if the statistics returned by the API have the expected format.

    test_phases:
        - setup:
            - Restart wazuh-manager service to apply configuration changes
        - test:
            - Simulate and connect an agent
            - Request the statistics of a particular daemon and agent from the API
            - Compare the obtained statistics with the json schema
            - Stop and delete the simulated agent
        - teardown:
            - Stop wazuh-manager

    wazuh_min_version: 4.4.0

    parameters:
        - test_metadata:
            type: dict
            brief: Get metadata from the module.
        - daemons_handler:
            type: fixture
            brief: Wrapper of a helper function to handle Wazuh daemons.

    assertions:
        - Check if the statistics returned by the API have the expected format.

    input_description:
        - The `cases_agent_statistics_format` file provides the test cases.
    """
    endpoint = test_metadata['endpoint']
    stats_schema_path = os.path.join(t2_statistics_template_path, f"{endpoint}_template.json")
    agents = create_agents(1, 'localhost')
    _, injector = connect(agents[0])

    route = f"/agents/{agents[0].id}/daemons/stats"
    params = f"?daemons_list={endpoint}"
    url = get_base_url() + route + params
    authentication_headers, _ = login()

    # Get Agent's daemon stats
    response = requests.get(url, headers=authentication_headers, verify=False)
    stats_schema = read_json_file(stats_schema_path)

    # Check if the API statistics response data meets the expected schema. Raise an exception if not.
    jsonschema.validate(instance=response.json(), schema=stats_schema)

    # Stop and delete simulated agent
    injector.stop_receive()
    remove_agents(agents[0].id, 'api')
