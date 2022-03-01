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

    phantom.custom_function(custom_function="Phishing_Investigation/regex_extract_email", parameters=parameters, name="extract_email_from_emailheaders", callback=custom_list_value_in_strings_3)

    return


def add_tag_vip_to_email_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_tag_vip_to_email_artifact() called")

    filtered_artifact_0_data_get_email_artifact_id = phantom.collect2(container=container, datapath=["filtered-data:get_email_artifact_id:condition_1:artifact:*.id","filtered-data:get_email_artifact_id:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'add_tag_vip_to_email_artifact' call
    for filtered_artifact_0_item_get_email_artifact_id in filtered_artifact_0_data_get_email_artifact_id:
        parameters.append({
            "name": None,
            "tags": "VIP",
            "label": None,
            "severity": None,
            "cef_field": None,
            "cef_value": None,
            "input_json": None,
            "artifact_id": filtered_artifact_0_item_get_email_artifact_id[0],
            "cef_data_type": None,
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


def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_2() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["finde_email_in_vip_list:action_result.summary.found_matches", ">", 0]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        get_email_artifact_id(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


def get_email_artifact_id(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_email_artifact_id() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.name", "==", "Email Artifact"]
        ],
        name="get_email_artifact_id:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        add_tag_vip_to_email_artifact(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


def finde_email_in_vip_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("finde_email_in_vip_list() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    extract_email_from_emailheaders_data = phantom.collect2(container=container, datapath=["extract_email_from_emailheaders:custom_function_result.data.*.email_address"])

    parameters = []

    # build parameters list for 'finde_email_in_vip_list' call
    for extract_email_from_emailheaders_data_item in extract_email_from_emailheaders_data:
        if extract_email_from_emailheaders_data_item[0] is not None:
            parameters.append({
                "exact_match": False,
                "list": "VIP",
                "values": extract_email_from_emailheaders_data_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("find listitem", parameters=parameters, name="finde_email_in_vip_list", assets=["phantom"], callback=finde_email_in_vip_list_callback)

    return


def finde_email_in_vip_list_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("finde_email_in_vip_list_callback() called")

    
    decision_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    debug_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


def debug_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("debug_2() called")

    finde_email_in_vip_list_result_data = phantom.collect2(container=container, datapath=["finde_email_in_vip_list:action_result.summary.found_matches","finde_email_in_vip_list:action_result.status","finde_email_in_vip_list:action_result.parameter.exact_match","finde_email_in_vip_list:action_result.summary","finde_email_in_vip_list:action_result.parameter.context.artifact_id"], action_results=results)

    finde_email_in_vip_list_summary_found_matches = [item[0] for item in finde_email_in_vip_list_result_data]
    finde_email_in_vip_list_result_item_1 = [item[1] for item in finde_email_in_vip_list_result_data]
    finde_email_in_vip_list_parameter_exact_match = [item[2] for item in finde_email_in_vip_list_result_data]
    finde_email_in_vip_list_result_item_3 = [item[3] for item in finde_email_in_vip_list_result_data]

    parameters = []

    parameters.append({
        "input_1": finde_email_in_vip_list_summary_found_matches,
        "input_2": finde_email_in_vip_list_result_item_1,
        "input_3": finde_email_in_vip_list_parameter_exact_match,
        "input_4": finde_email_in_vip_list_result_item_3,
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

    phantom.custom_function(custom_function="community/debug", parameters=parameters, name="debug_2")

    return


def custom_list_value_in_strings_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("custom_list_value_in_strings_3() called")

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

    phantom.custom_function(custom_function="Phishing_Investigation/custom_list_value_in_strings", parameters=parameters, name="custom_list_value_in_strings_3")

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