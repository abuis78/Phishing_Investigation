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
        url_parse_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


def url_parse_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("url_parse_2() called")

    filtered_artifact_0_data_filter_url_artifact = phantom.collect2(container=container, datapath=["filtered-data:filter_url_artifact:condition_1:artifact:*.cef.requestURL","filtered-data:filter_url_artifact:condition_1:artifact:*.id","filtered-data:filter_url_artifact:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'url_parse_2' call
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

    phantom.custom_function(custom_function="Phishing_Investigation/url_parse", parameters=parameters, name="url_parse_2", callback=format_2)

    return


def update_artifact_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("update_artifact_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    url_parse_2__result = phantom.collect2(container=container, datapath=["url_parse_2:custom_function_result.data.context_id"])
    format_2__as_list = phantom.get_format_data(name="format_2__as_list")

    parameters = []

    # build parameters list for 'update_artifact_1' call
    for url_parse_2__result_item in url_parse_2__result:
        for format_2__item in format_2__as_list:
            if url_parse_2__result_item[0] is not None:
                parameters.append({
                    "artifact_id": url_parse_2__result_item[0],
                    "cef_json": format_2__item,
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update artifact", parameters=parameters, name="update_artifact_1", assets=["phantom"])

    return


def format_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_2() called")

    template = """%%\n{{ \"scheme\": \"{0}\", \"output_url\": \"{1}\" }}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "url_parse_2:custom_function_result.data.scheme",
        "url_parse_2:custom_function_result.data.output_url"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_2")

    debug_3(container=container)

    return


def debug_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("debug_3() called")

    format_2 = phantom.get_format_data(name="format_2")
    format_2__as_list = phantom.get_format_data(name="format_2__as_list")

    parameters = []

    parameters.append({
        "input_1": format_2,
        "input_2": format_2__as_list,
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

    phantom.custom_function(custom_function="community/debug", parameters=parameters, name="debug_3")

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