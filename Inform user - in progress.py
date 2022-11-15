"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'filter_1' block
    filter_1(container=container)

    return

@phantom.playbook_block()
def regex_extract_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("regex_extract_email_1() called")

    filtered_artifact_0_data_filter_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:artifact:*.cef.fromEmail","filtered-data:filter_1:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'regex_extract_email_1' call
    for filtered_artifact_0_item_filter_1 in filtered_artifact_0_data_filter_1:
        parameters.append({
            "input_string": filtered_artifact_0_item_filter_1[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="Phishing_Investigation/regex_extract_email", parameters=parameters, name="regex_extract_email_1", callback=cf_encode_phankey_3)

    return


@phantom.playbook_block()
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_1() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.name", "==", "Email Artifact"]
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        regex_extract_email_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def cf_encode_phankey_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("cf_encode_phankey_3() called")

    id_value = container.get("id", None)
    regex_extract_email_1_data = phantom.collect2(container=container, datapath=["regex_extract_email_1:custom_function_result.data.*.email_address"])

    parameters = []

    # build parameters list for 'cf_encode_phankey_3' call
    for regex_extract_email_1_data_item in regex_extract_email_1_data:
        parameters.append({
            "user_email": regex_extract_email_1_data_item[0],
            "container_id": id_value,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="Phishing_Investigation/CF_encode_phankey", parameters=parameters, name="cf_encode_phankey_3", callback=email_subject)

    return


@phantom.playbook_block()
def email_subject(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("email_subject() called")

    template = """[Case-ID: {0}] The email that you have classified as suspicious is currently being analysed.\n"""

    # parameter list for template variable replacement
    parameters = [
        "container:id"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="email_subject")

    email_body(container=container)

    return


@phantom.playbook_block()
def email_body(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("email_body() called")

    template = """We would like to thank you for helping our company to deal safely with suspicious content.\n\nThe email will be analyzed immediately and you will receive a response within the next 5 minutes. \n\nWe ask for your patience.\n\n{0}"""

    # parameter list for template variable replacement
    parameters = [
        "cf_encode_phankey_3:custom_function_result.data.PHANKEY_body"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="email_body")

    send_email_1(container=container)

    return


@phantom.playbook_block()
def send_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("send_email_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    regex_extract_email_1_data = phantom.collect2(container=container, datapath=["regex_extract_email_1:custom_function_result.data.*.email_address"])
    email_body = phantom.get_format_data(name="email_body")
    email_subject = phantom.get_format_data(name="email_subject")

    parameters = []

    # build parameters list for 'send_email_1' call
    for regex_extract_email_1_data_item in regex_extract_email_1_data:
        if regex_extract_email_1_data_item[0] is not None and email_body is not None:
            parameters.append({
                "to": regex_extract_email_1_data_item[0],
                "body": email_body,
                "from": "it@soar4rookies.com",
                "subject": email_subject,
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("send email", parameters=parameters, name="send_email_1", assets=["smtp soc@soar4rookies.com"], callback=add_note_4)

    return


@phantom.playbook_block()
def add_note_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_note_4() called")

    email_body = phantom.get_format_data(name="email_body")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=email_body, note_format="markdown", note_type="general", title="Email to the customer")

    workbook_task_update_2(container=container)

    return


@phantom.playbook_block()
def workbook_task_update_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("workbook_task_update_2() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "owner": "current",
        "status": "complete",
        "container": id_value,
        "task_name": "Inform user",
        "note_title": "[Automated completion]",
        "note_content": "Automated completion",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="Phishing_Investigation/workbook_task_update", parameters=parameters, name="workbook_task_update_2")

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