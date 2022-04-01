"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'decision_if_email_artifact' block
    decision_if_email_artifact(container=container)

    return

def filter_artifact_for_email_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_artifact_for_email_artifact() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.name", "==", "Email Artifact"]
        ],
        name="filter_artifact_for_email_artifact:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        extract_source_identifier_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


def decision_if_email_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_if_email_artifact() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.name", "==", "Email Artifact"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        filter_artifact_for_email_artifact(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


def extract_source_identifier_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("extract_source_identifier_1() called")

    filtered_artifact_0_data_filter_artifact_for_email_artifact = phantom.collect2(container=container, datapath=["filtered-data:filter_artifact_for_email_artifact:condition_1:artifact:*.cef.bodyPart1","filtered-data:filter_artifact_for_email_artifact:condition_1:artifact:*.cef.emailHeaders.decodedSubject","filtered-data:filter_artifact_for_email_artifact:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'extract_source_identifier_1' call
    for filtered_artifact_0_item_filter_artifact_for_email_artifact in filtered_artifact_0_data_filter_artifact_for_email_artifact:
        parameters.append({
            "email_body": filtered_artifact_0_item_filter_artifact_for_email_artifact[0],
            "email_subject": filtered_artifact_0_item_filter_artifact_for_email_artifact[1],
            "source_identifier_prefix": "PMI",
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="Phishing_Investigation/extract_source_identifier", parameters=parameters, name="extract_source_identifier_1", callback=decision_2)

    return


def add_email_to_corresponding_contaiiner_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_email_to_corresponding_contaiiner_2() called")

    filtered_artifact_0_data_filter_artifact_for_email_artifact = phantom.collect2(container=container, datapath=["filtered-data:filter_artifact_for_email_artifact:condition_1:artifact:*.cef.bodyPart1","filtered-data:filter_artifact_for_email_artifact:condition_1:artifact:*.cef.emailHeaders.decodedSubject","filtered-data:filter_artifact_for_email_artifact:condition_1:artifact:*.id"])
    source_identifier_decode_4__result = phantom.collect2(container=container, datapath=["source_identifier_decode_4:custom_function_result.data.container_id"])

    parameters = []

    # build parameters list for 'add_email_to_corresponding_contaiiner_2' call
    for filtered_artifact_0_item_filter_artifact_for_email_artifact in filtered_artifact_0_data_filter_artifact_for_email_artifact:
        for source_identifier_decode_4__result_item in source_identifier_decode_4__result:
            parameters.append({
                "body": filtered_artifact_0_item_filter_artifact_for_email_artifact[0],
                "subject": filtered_artifact_0_item_filter_artifact_for_email_artifact[1],
                "container_id": source_identifier_decode_4__result_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="Phishing_Investigation/add_email_to_corresponding_contaiiner", parameters=parameters, name="add_email_to_corresponding_contaiiner_2")

    return


def source_identifier_decode_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("source_identifier_decode_4() called")

    extract_source_identifier_1__result = phantom.collect2(container=container, datapath=["extract_source_identifier_1:custom_function_result.data.source_identifier"])

    parameters = []

    # build parameters list for 'source_identifier_decode_4' call
    for extract_source_identifier_1__result_item in extract_source_identifier_1__result:
        parameters.append({
            "source_identifier": extract_source_identifier_1__result_item[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="Phishing_Investigation/source_identifier_decode", parameters=parameters, name="source_identifier_decode_4", callback=add_email_to_corresponding_contaiiner_2)

    return


def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_2() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["extract_source_identifier_1:custom_function_result.data.source_identifier", "==", False]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        add_comment_3(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    add_comment_6(action=action, success=success, container=container, results=results, handle=handle)

    return


def add_comment_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_comment_3() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="no source identifier found")

    return


def add_comment_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_comment_6() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="source identifier found")

    source_identifier_decode_4(container=container)

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