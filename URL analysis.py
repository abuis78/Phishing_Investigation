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
        artifact_update_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


def artifact_update_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("artifact_update_1() called")

    filtered_result_0_data_filter_reputation_check = phantom.collect2(container=container, datapath=["filtered-data:filter_reputation_check:condition_1:vt_url_reputation_check:action_result.parameter.context.artifact_id"])

    parameters = []

    # build parameters list for 'artifact_update_1' call
    for filtered_result_0_item_filter_reputation_check in filtered_result_0_data_filter_reputation_check:
        parameters.append({
            "artifact_id": filtered_result_0_item_filter_reputation_check[0],
            "name": None,
            "description": None,
            "label": None,
            "severity": None,
            "cef_field": None,
            "cef_value": None,
            "cef_data_type": None,
            "tags": "status_failed",
            "input_json": None,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="Phishing_Investigation/artifact_update", parameters=parameters, name="artifact_update_1")

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