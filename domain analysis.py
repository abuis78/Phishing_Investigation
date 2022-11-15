"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'decision_1' block
    decision_1(container=container)

    return

@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["Domain Artifact", "in", "artifact:*.name"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        filter_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    join_workbook_task_update_1(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_1() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.name", "==", "Domain Artifact"]
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        domain_reputation_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def join_workbook_task_update_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_workbook_task_update_1() called")

    if phantom.completed(custom_function_names=["noop_2"]):
        # call connected block "workbook_task_update_1"
        workbook_task_update_1(container=container, handle=handle)

    return


@phantom.playbook_block()
def workbook_task_update_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("workbook_task_update_1() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "owner": None,
        "status": None,
        "container": id_value,
        "task_name": "email artefacts",
        "note_title": "[Automated completion] Domain analysis",
        "note_content": "Domain analysis",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="Phishing_Investigation/workbook_task_update", parameters=parameters, name="workbook_task_update_1")

    return


@phantom.playbook_block()
def domain_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("domain_reputation_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.destinationDnsDomain","artifact:*.id"])

    parameters = []

    # build parameters list for 'domain_reputation_1' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "domain": container_artifact_item[0],
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("domain reputation", parameters=parameters, name="domain_reputation_1", assets=["virustotal v3"], callback=filter_status)

    return


@phantom.playbook_block()
def filter_status(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_status() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["domain_reputation_1:action_result.status", "==", "failed"]
        ],
        name="filter_status:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        update_artifact_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["domain_reputation_1:action_result.status", "==", "success"]
        ],
        name="filter_status:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        update_artifact_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


@phantom.playbook_block()
def update_artifact_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("update_artifact_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_result_0_data_filter_status = phantom.collect2(container=container, datapath=["filtered-data:filter_status:condition_1:domain_reputation_1:action_result.parameter.context.artifact_id"])

    parameters = []

    # build parameters list for 'update_artifact_1' call
    for filtered_result_0_item_filter_status in filtered_result_0_data_filter_status:
        if filtered_result_0_item_filter_status[0] is not None:
            parameters.append({
                "tags": "status_failed",
                "artifact_id": filtered_result_0_item_filter_status[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update artifact", parameters=parameters, name="update_artifact_1", assets=["phantom app asset"], callback=join_noop_2)

    return


@phantom.playbook_block()
def update_artifact_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("update_artifact_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    cef_json_formatted_string = phantom.format(
        container=container,
        template="""{{ \"VT_message\": \"{0}\" }}""",
        parameters=[
            "filtered-data:filter_status:condition_2:domain_reputation_1:action_result.message"
        ])

    filtered_result_0_data_filter_status = phantom.collect2(container=container, datapath=["filtered-data:filter_status:condition_2:domain_reputation_1:action_result.parameter.context.artifact_id"])

    parameters = []

    # build parameters list for 'update_artifact_2' call
    for filtered_result_0_item_filter_status in filtered_result_0_data_filter_status:
        if filtered_result_0_item_filter_status[0] is not None:
            parameters.append({
                "tags": "status_success",
                "cef_json": cef_json_formatted_string,
                "artifact_id": filtered_result_0_item_filter_status[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update artifact", parameters=parameters, name="update_artifact_2", assets=["phantom app asset"], callback=determinate_malicious)

    return


@phantom.playbook_block()
def determinate_malicious(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("determinate_malicious() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["filtered-data:filter_status:condition_2:domain_reputation_1:action_result.summary.malicious", ">", 0]
        ],
        name="determinate_malicious:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        update_artifact_3(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["filtered-data:filter_status:condition_2:domain_reputation_1:action_result.summary.malicious", "==", 0]
        ],
        name="determinate_malicious:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        update_artifact_4(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


@phantom.playbook_block()
def update_artifact_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("update_artifact_3() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_result_0_data_determinate_malicious = phantom.collect2(container=container, datapath=["filtered-data:determinate_malicious:condition_1:domain_reputation_1:action_result.parameter.context.artifact_id"])

    parameters = []

    # build parameters list for 'update_artifact_3' call
    for filtered_result_0_item_determinate_malicious in filtered_result_0_data_determinate_malicious:
        if filtered_result_0_item_determinate_malicious[0] is not None:
            parameters.append({
                "severity": "high",
                "artifact_id": filtered_result_0_item_determinate_malicious[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update artifact", parameters=parameters, name="update_artifact_3", assets=["phantom app asset"], callback=join_noop_2)

    return


@phantom.playbook_block()
def update_artifact_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("update_artifact_4() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_result_0_data_determinate_malicious = phantom.collect2(container=container, datapath=["filtered-data:determinate_malicious:condition_2:domain_reputation_1:action_result.parameter.context.artifact_id"])

    parameters = []

    # build parameters list for 'update_artifact_4' call
    for filtered_result_0_item_determinate_malicious in filtered_result_0_data_determinate_malicious:
        if filtered_result_0_item_determinate_malicious[0] is not None:
            parameters.append({
                "severity": "low",
                "artifact_id": filtered_result_0_item_determinate_malicious[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update artifact", parameters=parameters, name="update_artifact_4", assets=["phantom app asset"], callback=join_noop_2)

    return


@phantom.playbook_block()
def join_noop_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_noop_2() called")

    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key="join_noop_2_called"):
        return

    # save the state that the joined function has now been called
    phantom.save_run_data(key="join_noop_2_called", value="noop_2")

    # call connected block "noop_2"
    noop_2(container=container, handle=handle)

    return


@phantom.playbook_block()
def noop_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("noop_2() called")

    parameters = [{}]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="Phishing_Investigation/noop", parameters=parameters, name="noop_2", callback=join_workbook_task_update_1)

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