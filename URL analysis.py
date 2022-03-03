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
        separate_a_url_into_components(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


def separate_a_url_into_components(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("separate_a_url_into_components() called")

    filtered_artifact_0_data_filter_url_artifact = phantom.collect2(container=container, datapath=["filtered-data:filter_url_artifact:condition_1:artifact:*.cef.requestURL","filtered-data:filter_url_artifact:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'separate_a_url_into_components' call
    for filtered_artifact_0_item_filter_url_artifact in filtered_artifact_0_data_filter_url_artifact:
        parameters.append({
            "input_url": filtered_artifact_0_item_filter_url_artifact[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="Phishing_Investigation/url_parse", parameters=parameters, name="separate_a_url_into_components", callback=update_artifact_1)

    return


def update_artifact_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("update_artifact_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    cef_json_formatted_string = phantom.format(
        container=container,
        template="""{{ \"scheme\": \"{0}\",\"netloc\": \"{1}\",\"path\": \"{2}\",\"params\": \"{3}\",\"query\": \"{4}\",\"fragment\": \"{5}\",\"output_url\": \"{6}\"  \n\n}}\n""",
        parameters=[
            "separate_a_url_into_components:custom_function_result.data.scheme",
            "separate_a_url_into_components:custom_function_result.data.netloc",
            "separate_a_url_into_components:custom_function_result.data.path",
            "separate_a_url_into_components:custom_function_result.data.params",
            "separate_a_url_into_components:custom_function_result.data.query",
            "separate_a_url_into_components:custom_function_result.data.fragment",
            "separate_a_url_into_components:custom_function_result.data.output_url"
        ])

    filtered_artifact_0_data_filter_url_artifact = phantom.collect2(container=container, datapath=["filtered-data:filter_url_artifact:condition_1:artifact:*.id","filtered-data:filter_url_artifact:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'update_artifact_1' call
    for filtered_artifact_0_item_filter_url_artifact in filtered_artifact_0_data_filter_url_artifact:
        if filtered_artifact_0_item_filter_url_artifact[0] is not None:
            parameters.append({
                "artifact_id": filtered_artifact_0_item_filter_url_artifact[0],
                "cef_json": cef_json_formatted_string,
                "context": {'artifact_id': filtered_artifact_0_item_filter_url_artifact[1]},
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