"""
In this playbook the analysis of the sender takes place. It searches for specific keywords in the email body and subject, matches autohrized domains, and performs a VIP check. \nThe corrolation of the single elements defines a risk score for the sender.
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
def extract_email_from_emailheaders(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("extract_email_from_emailheaders() called")

    filtered_artifact_0_data_filter_email_artifact = phantom.collect2(container=container, datapath=["filtered-data:filter_email_artifact:condition_1:artifact:*.cef.emailHeaders.From","filtered-data:filter_email_artifact:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'extract_email_from_emailheaders' call
    for filtered_artifact_0_item_filter_email_artifact in filtered_artifact_0_data_filter_email_artifact:
        parameters.append({
            "input_string": filtered_artifact_0_item_filter_email_artifact[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="Phishing_Investigation/regex_extract_email", parameters=parameters, name="extract_email_from_emailheaders", callback=format_email_in_str)

    return


@phantom.playbook_block()
def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_2() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["matching_email_with_list:custom_function_result.data.match_count", ">", 0]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        update_artifact_2(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    join_vip_path(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def matching_email_with_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("matching_email_with_list() called")

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

    phantom.custom_function(custom_function="Phishing_Investigation/custom_list_value_in_strings", parameters=parameters, name="matching_email_with_list", callback=decision_2)

    return


@phantom.playbook_block()
def join_vip_path(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_vip_path() called")

    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key="join_vip_path_called"):
        return

    if phantom.completed(action_names=["update_artifact_2"]):
        # save the state that the joined function has now been called
        phantom.save_run_data(key="join_vip_path_called", value="vip_path")

        # call connected block "vip_path"
        vip_path(container=container, handle=handle)

    return


@phantom.playbook_block()
def vip_path(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("vip_path() called")

    parameters = [{}]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="Phishing_Investigation/noop", parameters=parameters, name="vip_path", callback=extract_domain_from_dkim_signature)

    return


@phantom.playbook_block()
def extract_domain_from_dkim_signature(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("extract_domain_from_dkim_signature() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.emailHeaders.DKIM-Signature"])
    extract_email_from_emailheaders_data = phantom.collect2(container=container, datapath=["extract_email_from_emailheaders:custom_function_result.data.*.domain"])

    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]
    extract_email_from_emailheaders_data___domain = [item[0] for item in extract_email_from_emailheaders_data]

    extract_domain_from_dkim_signature__dkim_domain_check_result = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    import re
    phantom.debug(container_artifact_cef_item_0)
    phantom.debug(extract_email_from_emailheaders_data___domain)
    domain_regex = r'(((?!-))(xn--)?[a-z0-9][a-z0-9-_]{0,61}[a-z0-9]{0,1}\.(xn--)?([a-z0-9\-]{1,61}|[a-z0-9-]{1,30}\.[a-z]{2,}))'
    for domain in re.findall(domain_regex, str(container_artifact_cef_item_0), re.IGNORECASE):
        phantom.debug(domain[0])
        dkim_domain = domain[0]
        
    if dkim_domain == extract_email_from_emailheaders_data___domain[0]:
        phantom.debug('same Domain')
        extract_domain_from_dkim_signature__dkim_domain_check_result = True
        
    else:
        phantom.debug('not same Domainn')
        extract_domain_from_dkim_signature__dkim_domain_check_result = False
    
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="extract_domain_from_dkim_signature:dkim_domain_check_result", value=json.dumps(extract_domain_from_dkim_signature__dkim_domain_check_result))

    dkim_check(container=container)

    return


@phantom.playbook_block()
def dkim_check(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("dkim_check() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["extract_domain_from_dkim_signature:custom_function:dkim_domain_check_result", "==", True]
        ],
        scope="all")

    # call connected blocks if condition 1 matched
    if found_match_1:
        convert_tag_list_into_string(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    join_dkim_path(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def join_dkim_path(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_dkim_path() called")

    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key="join_dkim_path_called"):
        return

    if phantom.completed(action_names=["update_artifact_3"]):
        # save the state that the joined function has now been called
        phantom.save_run_data(key="join_dkim_path_called", value="dkim_path")

        # call connected block "dkim_path"
        dkim_path(container=container, handle=handle)

    return


@phantom.playbook_block()
def dkim_path(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("dkim_path() called")

    parameters = [{}]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="Phishing_Investigation/noop", parameters=parameters, name="dkim_path", callback=keyword_mention_in_email)

    return


@phantom.playbook_block()
def convert_tag_list_into_string(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("convert_tag_list_into_string() called")

    create_email_artefact__result = phantom.collect2(container=container, datapath=["create_email_artefact:custom_function_result.data.artifact_id"], scope="all")

    create_email_artefact_data_artifact_id = [item[0] for item in create_email_artefact__result]

    convert_tag_list_into_string__tag_str_list = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    phantom.debug(create_email_artefact_data_artifact_id[0])
    url = phantom.build_phantom_rest_url('artifact', create_email_artefact_data_artifact_id[0], 'tags')
    response = phantom.requests.get(url,verify=False,)
    phantom.debug("phantom returned status code {} with message {}".format(response.status_code, response.text))
    
    artifatc_tag_list = response.json()['tags']
    phantom.debug('Tags from Artifakts {}'.format(artifatc_tag_list))
    
    # this builds the Tag list
    #lat_list = [item for sublist in artifatc_tag_list for item in sublist]
    #phantom.debug(lat_list)
    
    tag_list = ','.join(artifatc_tag_list)
    
    convert_tag_list_into_string__tag_str_list = tag_list + ', internal'

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="convert_tag_list_into_string:tag_str_list", value=json.dumps(convert_tag_list_into_string__tag_str_list))

    update_artifact_3(container=container)

    return


@phantom.playbook_block()
def create_email_artefact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("create_email_artefact() called")

    id_value = container.get("id", None)
    format_email_in_str = phantom.get_format_data(name="format_email_in_str")

    parameters = []

    parameters.append({
        "name": "Sender email address",
        "tags": None,
        "label": " artifact",
        "severity": "low",
        "cef_field": "from",
        "cef_value": format_email_in_str,
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

    phantom.custom_function(custom_function="Phishing_Investigation/artifact_create", parameters=parameters, name="create_email_artefact", callback=matching_email_with_list)

    return


@phantom.playbook_block()
def format_email_in_str(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_email_in_str() called")

    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "extract_email_from_emailheaders:custom_function_result.data.*.email_address"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_email_in_str")

    create_email_artefact(container=container)

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
        extract_email_from_emailheaders(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def decision_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_4() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["keyword_mention_in_email:custom_function_result.data.match_count_result", "==", True]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        format_keywoard_list(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    join_email_address_keyword_path(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def update_artifact_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("update_artifact_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    cef_json_formatted_string = phantom.format(
        container=container,
        template="""{{ \"keywoards_dedetcted\": \"{0}\" }}\n""",
        parameters=[
            "format_keywoard_list:formatted_data"
        ])

    create_email_artefact__result = phantom.collect2(container=container, datapath=["create_email_artefact:custom_function_result.data.artifact_id"])

    parameters = []

    # build parameters list for 'update_artifact_1' call
    for create_email_artefact__result_item in create_email_artefact__result:
        if create_email_artefact__result_item[0] is not None:
            parameters.append({
                "cef_json": cef_json_formatted_string,
                "artifact_id": create_email_artefact__result_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update artifact", parameters=parameters, name="update_artifact_1", assets=["phantom app asset"], callback=join_email_address_keyword_path)

    return


@phantom.playbook_block()
def format_keywoard_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_keywoard_list() called")

    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "keyword_mention_in_email:custom_function_result.data.match_keyword_list"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_keywoard_list")

    update_artifact_1(container=container)

    return


@phantom.playbook_block()
def join_email_address_keyword_path(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_email_address_keyword_path() called")

    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key="join_email_address_keyword_path_called"):
        return

    if phantom.completed(custom_function_names=["keyword_mention_in_email"]):
        # save the state that the joined function has now been called
        phantom.save_run_data(key="join_email_address_keyword_path_called", value="email_address_keyword_path")

        # call connected block "email_address_keyword_path"
        email_address_keyword_path(container=container, handle=handle)

    return


@phantom.playbook_block()
def email_address_keyword_path(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("email_address_keyword_path() called")

    parameters = [{}]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="Phishing_Investigation/noop", parameters=parameters, name="email_address_keyword_path", callback=lookup_email_from)

    return


@phantom.playbook_block()
def keyword_mention_in_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("keyword_mention_in_email() called")

    filtered_artifact_0_data_filter_email_artifact = phantom.collect2(container=container, datapath=["filtered-data:filter_email_artifact:condition_1:artifact:*.cef.emailHeaders.From","filtered-data:filter_email_artifact:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'keyword_mention_in_email' call
    for filtered_artifact_0_item_filter_email_artifact in filtered_artifact_0_data_filter_email_artifact:
        parameters.append({
            "liste_name": "Company_Keywords",
            "string_searched": filtered_artifact_0_item_filter_email_artifact[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="Phishing_Investigation/keyword_search", parameters=parameters, name="keyword_mention_in_email", callback=decision_4)

    return


@phantom.playbook_block()
def update_artifact_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("update_artifact_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    create_email_artefact__result = phantom.collect2(container=container, datapath=["create_email_artefact:custom_function_result.data.artifact_id"])

    parameters = []

    # build parameters list for 'update_artifact_2' call
    for create_email_artefact__result_item in create_email_artefact__result:
        if create_email_artefact__result_item[0] is not None:
            parameters.append({
                "tags": "VIP",
                "artifact_id": create_email_artefact__result_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update artifact", parameters=parameters, name="update_artifact_2", assets=["phantom app asset"], callback=join_vip_path)

    return


@phantom.playbook_block()
def update_artifact_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("update_artifact_3() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    create_email_artefact__result = phantom.collect2(container=container, datapath=["create_email_artefact:custom_function_result.data.artifact_id"])
    convert_tag_list_into_string__tag_str_list = json.loads(phantom.get_run_data(key="convert_tag_list_into_string:tag_str_list"))

    parameters = []

    # build parameters list for 'update_artifact_3' call
    for create_email_artefact__result_item in create_email_artefact__result:
        if create_email_artefact__result_item[0] is not None:
            parameters.append({
                "tags": convert_tag_list_into_string__tag_str_list,
                "artifact_id": create_email_artefact__result_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update artifact", parameters=parameters, name="update_artifact_3", assets=["phantom app asset"], callback=join_dkim_path)

    return


@phantom.playbook_block()
def lookup_email_from(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("lookup_email_from() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    extract_email_from_emailheaders_data = phantom.collect2(container=container, datapath=["extract_email_from_emailheaders:custom_function_result.data.*.email_address"])

    parameters = []

    # build parameters list for 'lookup_email_from' call
    for extract_email_from_emailheaders_data_item in extract_email_from_emailheaders_data:
        if extract_email_from_emailheaders_data_item[0] is not None:
            parameters.append({
                "email": extract_email_from_emailheaders_data_item[0],
                "truncate": False,
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("lookup email", parameters=parameters, name="lookup_email_from", assets=["have i been pwned"], callback=total_breaches_decision)

    return


@phantom.playbook_block()
def total_breaches_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("total_breaches_decision() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["lookup_email_from:action_result.summary.total_breaches", ">", 0]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        pin_data(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    join_workbook_task_update_4(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def pin_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("pin_2() called")

    extract_email_from_emailheaders_data = phantom.collect2(container=container, datapath=["extract_email_from_emailheaders:custom_function_result.data.*.email_address"])
    pin_data = phantom.get_format_data(name="pin_data")

    extract_email_from_emailheaders_data___email_address = [item[0] for item in extract_email_from_emailheaders_data]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, data=pin_data, message=extract_email_from_emailheaders_data___email_address, pin_style="red", pin_type="card")

    join_workbook_task_update_4(container=container)

    return


@phantom.playbook_block()
def pin_data(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("pin_data() called")

    template = """{0}\n"""

    # parameter list for template variable replacement
    parameters = [
        "lookup_email_from:action_result.message"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="pin_data")

    pin_2(container=container)

    return


@phantom.playbook_block()
def join_workbook_task_update_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_workbook_task_update_4() called")

    if phantom.completed(action_names=["lookup_email_from"]):
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
        "task_name": "sende email",
        "note_title": "[Automated completion] Analysis of the sende email",
        "note_content": "Analysis of the sende email",
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