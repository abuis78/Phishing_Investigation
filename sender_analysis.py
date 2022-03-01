"""
In this playbook the analysis of the sender takes place. It searches for specific keywords in the email body and subject, matches autohrized domains, and performs a VIP check. \nThe corrolation of the single elements defines a risk score for the sender.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'extract_email_from_emailheaders' block
    extract_email_from_emailheaders(container=container)

    return

def extract_email_from_emailheaders(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("extract_email_from_emailheaders() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.emailHeaders.From","artifact:*.id"])

    parameters = []

    # build parameters list for 'extract_email_from_emailheaders' call
    for container_artifact_item in container_artifact_data:
        parameters.append({
            "input_string": container_artifact_item[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="Phishing_Investigation/regex_extract_email", parameters=parameters, name="extract_email_from_emailheaders", callback=custom_list_value_in_strings_11)

    return


def filter_email_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_email_artifact() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.name", "==", "Email Artifact"]
        ],
        name="filter_email_artifact:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        pass

    return


def add_tag_vip_to_email_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_tag_vip_to_email_artifact() called")

    filtered_artifact_0_data_filter_email_artifact = phantom.collect2(container=container, datapath=["filtered-data:filter_email_artifact:condition_1:artifact:*.id","filtered-data:filter_email_artifact:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'add_tag_vip_to_email_artifact' call
    for filtered_artifact_0_item_filter_email_artifact in filtered_artifact_0_data_filter_email_artifact:
        parameters.append({
            "artifact_id": filtered_artifact_0_item_filter_email_artifact[0],
            "name": None,
            "label": None,
            "severity": None,
            "cef_field": None,
            "cef_value": None,
            "cef_data_type": None,
            "tags": "VIP",
            "input_json": None,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="Phishing_Investigation/artifact_update", parameters=parameters, name="add_tag_vip_to_email_artifact")

    return


def debug_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("debug_8() called")

    custom_list_value_in_strings_11__result = phantom.collect2(container=container, datapath=["custom_list_value_in_strings_11:custom_function_result.data.match_count","custom_list_value_in_strings_11:custom_function_result.data.miss_count"])
    custom_list_value_in_strings_11_data_matches = phantom.collect2(container=container, datapath=["custom_list_value_in_strings_11:custom_function_result.data.matches.*.match"])
    extract_email_from_emailheaders_data = phantom.collect2(container=container, datapath=["extract_email_from_emailheaders:custom_function_result.data.*.email_address"])

    custom_list_value_in_strings_11_data_match_count = [item[0] for item in custom_list_value_in_strings_11__result]
    custom_list_value_in_strings_11_data_miss_count = [item[1] for item in custom_list_value_in_strings_11__result]
    custom_list_value_in_strings_11_data_matches___match = [item[0] for item in custom_list_value_in_strings_11_data_matches]
    extract_email_from_emailheaders_data___email_address = [item[0] for item in extract_email_from_emailheaders_data]

    parameters = []

    parameters.append({
        "input_1": custom_list_value_in_strings_11_data_match_count,
        "input_2": custom_list_value_in_strings_11_data_miss_count,
        "input_3": custom_list_value_in_strings_11_data_matches___match,
        "input_4": extract_email_from_emailheaders_data___email_address,
        "input_5": None,
        "input_6": None,
        "input_7": None,
        "input_8": None,
        "input_9": None,
        "input_10": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/debug", parameters=parameters, name="debug_8")

    return


def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_2() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["extract_email_from_emailheaders:custom_function_result.data.*.email_address", "in", "custom_list:VIP"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        return

    return


def filter_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_3() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["format_1:formatted_data", "in", "custom_list:VIP"]
        ],
        name="filter_3:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        pass

    return


def custom_list_value_in_strings_11(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("custom_list_value_in_strings_11() called")

    extract_email_from_emailheaders_data = phantom.collect2(container=container, datapath=["extract_email_from_emailheaders:custom_function_result.data.*.email_address"])

    extract_email_from_emailheaders_data___email_address = [item[0] for item in extract_email_from_emailheaders_data]

    parameters = []

    parameters.append({
        "custom_list": "VIP",
        "comparison_strings": extract_email_from_emailheaders_data___email_address,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="Phishing_Investigation/custom_list_value_in_strings", parameters=parameters, name="custom_list_value_in_strings_11", callback=debug_8)

    return


def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    ################################################################################
    ## Custom Code End
    ################################################################################

    return