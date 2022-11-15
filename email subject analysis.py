"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'filter_email_artifact' block
    filter_email_artifact(container=container)

    return

@phantom.playbook_block()
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
        keyword_search_in_subject(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def keyword_search_in_subject(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("keyword_search_in_subject() called")

    filtered_artifact_0_data_filter_email_artifact = phantom.collect2(container=container, datapath=["filtered-data:filter_email_artifact:condition_1:artifact:*.cef.emailHeaders.Subject","filtered-data:filter_email_artifact:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'keyword_search_in_subject' call
    for filtered_artifact_0_item_filter_email_artifact in filtered_artifact_0_data_filter_email_artifact:
        parameters.append({
            "liste_name": "Suspicious_keywords",
            "string_searched": filtered_artifact_0_item_filter_email_artifact[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="Phishing_Investigation/keyword_search", parameters=parameters, name="keyword_search_in_subject", callback=decision_1)

    return


@phantom.playbook_block()
def keyword_search_in_decodedsubject(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("keyword_search_in_decodedsubject() called")

    filtered_artifact_0_data_filter_email_artifact = phantom.collect2(container=container, datapath=["filtered-data:filter_email_artifact:condition_1:artifact:*.cef.emailHeaders.decodedSubject","filtered-data:filter_email_artifact:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'keyword_search_in_decodedsubject' call
    for filtered_artifact_0_item_filter_email_artifact in filtered_artifact_0_data_filter_email_artifact:
        parameters.append({
            "liste_name": "Suspicious_keywords",
            "string_searched": filtered_artifact_0_item_filter_email_artifact[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="Phishing_Investigation/keyword_search", parameters=parameters, name="keyword_search_in_decodedsubject")

    return


@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["keyword_search_in_subject:custom_function_result.data.match_count_result", "==", True]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        create_subject_artifact(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    join_workbook_task_update_4(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def create_subject_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("create_subject_artifact() called")

    id_value = container.get("id", None)
    filtered_artifact_0_data_filter_email_artifact = phantom.collect2(container=container, datapath=["filtered-data:filter_email_artifact:condition_1:artifact:*.cef.emailHeaders.Subject","filtered-data:filter_email_artifact:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'create_subject_artifact' call
    for filtered_artifact_0_item_filter_email_artifact in filtered_artifact_0_data_filter_email_artifact:
        parameters.append({
            "name": "eMail Subject",
            "tags": None,
            "label": "artifact",
            "severity": "Low",
            "cef_field": "subject",
            "cef_value": filtered_artifact_0_item_filter_email_artifact[0],
            "container": id_value,
            "input_json": None,
            "cef_data_type": None,
            "run_automation": None,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="Phishing_Investigation/artifact_create", parameters=parameters, name="create_subject_artifact", callback=update_artifact_1)

    return


@phantom.playbook_block()
def update_artifact_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("update_artifact_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    cef_json_formatted_string = phantom.format(
        container=container,
        template="""{{ \"keywoards_dedetcted\": \"{0}\" }}\n""",
        parameters=[
            "keyword_search_in_subject:custom_function_result.data.match_keyword_list"
        ])

    create_subject_artifact__result = phantom.collect2(container=container, datapath=["create_subject_artifact:custom_function_result.data.artifact_id"])

    parameters = []

    # build parameters list for 'update_artifact_1' call
    for create_subject_artifact__result_item in create_subject_artifact__result:
        if create_subject_artifact__result_item[0] is not None:
            parameters.append({
                "cef_json": cef_json_formatted_string,
                "severity": "medium",
                "artifact_id": create_subject_artifact__result_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update artifact", parameters=parameters, name="update_artifact_1", assets=["phantom app asset"], callback=join_workbook_task_update_4)

    return


@phantom.playbook_block()
def join_workbook_task_update_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_workbook_task_update_4() called")

    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key="join_workbook_task_update_4_called"):
        return

    # save the state that the joined function has now been called
    phantom.save_run_data(key="join_workbook_task_update_4_called", value="workbook_task_update_4")

    # call connected block "workbook_task_update_4"
    workbook_task_update_4(container=container, handle=handle)

    return


@phantom.playbook_block()
def workbook_task_update_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("workbook_task_update_4() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "owner": "current",
        "status": "complete",
        "container": id_value,
        "task_name": "subject",
        "note_title": "[Automated completion] Sender analysis",
        "note_content": " Sender analysis",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="Phishing_Investigation/workbook_task_update", parameters=parameters, name="workbook_task_update_4")

    return


@phantom.playbook_block()
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