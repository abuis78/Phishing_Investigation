"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'filter_url_artifact' block
    filter_url_artifact(container=container)

    return

def filter_url_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_url_artifact() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.name", "==", "URL Artifact"]
        ],
        name="filter_url_artifact:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        parse_url_its_component(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


def parse_url_its_component(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("parse_url_its_component() called")

    filtered_artifact_0_data_filter_url_artifact = phantom.collect2(container=container, datapath=["filtered-data:filter_url_artifact:condition_1:artifact:*.cef.requestURL","filtered-data:filter_url_artifact:condition_1:artifact:*.id","filtered-data:filter_url_artifact:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'parse_url_its_component' call
    for filtered_artifact_0_item_filter_url_artifact in filtered_artifact_0_data_filter_url_artifact:
        parameters.append({
            "input_url": filtered_artifact_0_item_filter_url_artifact[0],
            "artifact_id": filtered_artifact_0_item_filter_url_artifact[1],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="Phishing_Investigation/url_parse_update_coresponding_artifact", parameters=parameters, name="parse_url_its_component", callback=vt_url_reputation_check)

    return


def vt_url_reputation_check(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("vt_url_reputation_check() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_artifact_0_data_filter_url_artifact = phantom.collect2(container=container, datapath=["filtered-data:filter_url_artifact:condition_1:artifact:*.cef.requestURL","filtered-data:filter_url_artifact:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'vt_url_reputation_check' call
    for filtered_artifact_0_item_filter_url_artifact in filtered_artifact_0_data_filter_url_artifact:
        if filtered_artifact_0_item_filter_url_artifact[0] is not None:
            parameters.append({
                "url": filtered_artifact_0_item_filter_url_artifact[0],
                "context": {'artifact_id': filtered_artifact_0_item_filter_url_artifact[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("url reputation", parameters=parameters, name="vt_url_reputation_check", assets=["virustotal v3"], callback=filter_reputation_check)

    return


def filter_reputation_check(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_reputation_check() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["vt_url_reputation_check:action_result.status", "==", "failed"]
        ],
        name="filter_reputation_check:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        update_artifact_add_tag_status_failed(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["vt_url_reputation_check:action_result.status", "==", "success"]
        ],
        name="filter_reputation_check:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        update_artifact_add_tag_status_success_and_message(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


def update_artifact_add_tag_status_failed(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("update_artifact_add_tag_status_failed() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_result_0_data_filter_reputation_check = phantom.collect2(container=container, datapath=["filtered-data:filter_reputation_check:condition_1:vt_url_reputation_check:action_result.parameter.context.artifact_id"])

    parameters = []

    # build parameters list for 'update_artifact_add_tag_status_failed' call
    for filtered_result_0_item_filter_reputation_check in filtered_result_0_data_filter_reputation_check:
        if filtered_result_0_item_filter_reputation_check[0] is not None:
            parameters.append({
                "tags": "status_failed",
                "artifact_id": filtered_result_0_item_filter_reputation_check[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update artifact", parameters=parameters, name="update_artifact_add_tag_status_failed", assets=["phantom"])

    return


def update_artifact_add_tag_status_success_and_message(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("update_artifact_add_tag_status_success_and_message() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    cef_json_formatted_string = phantom.format(
        container=container,
        template="""{{ \"VT_message\": \"{0}\" }}\n""",
        parameters=[
            "filtered-data:filter_reputation_check:condition_2:vt_url_reputation_check:action_result.message"
        ])

    filtered_result_0_data_filter_reputation_check = phantom.collect2(container=container, datapath=["filtered-data:filter_reputation_check:condition_2:vt_url_reputation_check:action_result.parameter.context.artifact_id"])

    parameters = []

    # build parameters list for 'update_artifact_add_tag_status_success_and_message' call
    for filtered_result_0_item_filter_reputation_check in filtered_result_0_data_filter_reputation_check:
        if filtered_result_0_item_filter_reputation_check[0] is not None:
            parameters.append({
                "tags": "status_success",
                "cef_json": cef_json_formatted_string,
                "artifact_id": filtered_result_0_item_filter_reputation_check[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update artifact", parameters=parameters, name="update_artifact_add_tag_status_success_and_message", assets=["phantom"], callback=severity_set_based_on_malicious)

    return


def severity_set_based_on_malicious(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("severity_set_based_on_malicious() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["filtered-data:filter_reputation_check:condition_2:vt_url_reputation_check:action_result.summary.malicious", ">", 0]
        ],
        name="severity_set_based_on_malicious:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        set_artifact_status_high(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["filtered-data:filter_reputation_check:condition_2:vt_url_reputation_check:action_result.summary.malicious", "==", 0]
        ],
        name="severity_set_based_on_malicious:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        set_artifact_status_low(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


def set_artifact_status_high(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("set_artifact_status_high() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_result_0_data_severity_set_based_on_malicious = phantom.collect2(container=container, datapath=["filtered-data:severity_set_based_on_malicious:condition_1:vt_url_reputation_check:action_result.parameter.context.artifact_id"])

    parameters = []

    # build parameters list for 'set_artifact_status_high' call
    for filtered_result_0_item_severity_set_based_on_malicious in filtered_result_0_data_severity_set_based_on_malicious:
        if filtered_result_0_item_severity_set_based_on_malicious[0] is not None:
            parameters.append({
                "severity": "high",
                "artifact_id": filtered_result_0_item_severity_set_based_on_malicious[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update artifact", parameters=parameters, name="set_artifact_status_high", assets=["phantom"], callback=join_url_reputation_path)

    return


def set_artifact_status_low(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("set_artifact_status_low() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_result_0_data_severity_set_based_on_malicious = phantom.collect2(container=container, datapath=["filtered-data:severity_set_based_on_malicious:condition_2:vt_url_reputation_check:action_result.parameter.context.artifact_id"])

    parameters = []

    # build parameters list for 'set_artifact_status_low' call
    for filtered_result_0_item_severity_set_based_on_malicious in filtered_result_0_data_severity_set_based_on_malicious:
        if filtered_result_0_item_severity_set_based_on_malicious[0] is not None:
            parameters.append({
                "artifact_id": filtered_result_0_item_severity_set_based_on_malicious[0],
                "severity": "low",
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update artifact", parameters=parameters, name="set_artifact_status_low", assets=["phantom"], callback=join_url_reputation_path)

    return


def join_url_reputation_path(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_url_reputation_path() called")

    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key="join_url_reputation_path_called"):
        return

    # save the state that the joined function has now been called
    phantom.save_run_data(key="join_url_reputation_path_called", value="url_reputation_path")

    # call connected block "url_reputation_path"
    url_reputation_path(container=container, handle=handle)

    return


def url_reputation_path(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("url_reputation_path() called")

    parameters = [{}]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="DB_POC_final/noop", parameters=parameters, name="url_reputation_path", callback=debug_2)

    return


def debug_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("debug_2() called")

    parameters = []

    parameters.append({
        "input_1": "vt_url_reputation_check:object",
        "input_2": None,
        "input_3": None,
        "input_4": None,
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