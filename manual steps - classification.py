"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'manual_step_classification' block
    manual_step_classification(container=container)

    return

def manual_step_classification(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("manual_step_classification() called")

    # set user and message variables for phantom.prompt call
    effective_user_id = phantom.get_effective_user()
    url = phantom.build_phantom_rest_url('ph_user', effective_user_id)
    effective_user = phantom.requests.get(url, verify=False).json()
    phantom.debug(effective_user['username'])

    user = effective_user['username']
    message = """## I have a question?\nDo any manual steps need to be taken?\nPlease select ..."""

    # parameter list for template variable replacement
    parameters = []

    # responses
    response_types = [
        {
            "prompt": "DLP checks?",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No"
                ],
            },
        },
        {
            "prompt": "VIP checks?",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No"
                ],
            },
        },
        {
            "prompt": "Check attachment before uploading them to cloud sandbox ?",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No"
                ],
            },
        }
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="manual_step_classification", parameters=parameters, response_types=response_types, callback=decision_dlp_checks)

    return

def decision_dlp_checks(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_dlp_checks() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["manual_step_classification:action_result.summary.responses.0", "==", "Yes"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        workbook_add_3(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    join_decision_2(action=action, success=success, container=container, results=results, handle=handle)

    return


def join_decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_decision_2() called")

    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key="join_decision_2_called"):
        return

    if phantom.completed(action_names=["manual_step_classification"]):
        # save the state that the joined function has now been called
        phantom.save_run_data(key="join_decision_2_called", value="decision_2")

        # call connected block "decision_2"
        decision_2(container=container, handle=handle)

    return


def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_2() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["manual_step_classification:action_result.summary.responses.1", "==", "Yes"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        workbook_add_2(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    join_decision_3(action=action, success=success, container=container, results=results, handle=handle)

    return


def workbook_add_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("workbook_add_2() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "workbook": "Vip checks",
        "container": id_value,
        "start_workbook": False,
        "check_for_existing_workbook": True,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="DB_POC_final/workbook_add", parameters=parameters, name="workbook_add_2", callback=join_decision_3)

    return


def workbook_add_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("workbook_add_3() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "workbook": "DLP checks",
        "container": id_value,
        "start_workbook": False,
        "check_for_existing_workbook": True,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="DB_POC_final/workbook_add", parameters=parameters, name="workbook_add_3", callback=join_decision_2)

    return


def join_decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_decision_3() called")

    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key="join_decision_3_called"):
        return

    if phantom.completed(action_names=["manual_step_classification"]):
        # save the state that the joined function has now been called
        phantom.save_run_data(key="join_decision_3_called", value="decision_3")

        # call connected block "decision_3"
        decision_3(container=container, handle=handle)

    return


def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_3() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["manual_step_classification:action_result.summary.responses.2", "==", "Yes"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        workbook_add_4(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


def workbook_add_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("workbook_add_4() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "workbook": "Check attachment",
        "container": id_value,
        "start_workbook": False,
        "check_for_existing_workbook": True,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="DB_POC_final/workbook_add", parameters=parameters, name="workbook_add_4")

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